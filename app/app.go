package app

import (
	"context"
	"errors"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/user"
	"mini-pasuki2/pasuki2"
	"net/http"
	"os"

	"entgo.io/ent/dialect"

	"entgo.io/ent/dialect/sql"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	_ "github.com/go-sql-driver/mysql"
)

const ENT_MAX_CONN = 3

type App struct {
	ent       *ent.Client
	pasuki    *pasuki2.Pasuki2
	validator *validator.Validate
}

type RegisterStartRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
}

type RegisterFinishRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
	// (!) this is passkey credential id, not our database id
	Id                      string `form:"id" validate:"required,base64rawurl,min=22"`
	Type                    string `form:"type" validate:"required,eq=public-key"`
	AuthenticatorAttachment string `form:"authenticatorAttachment" validata:"omitempty,oneof=platform cross-platform"`
	AttestationObject       string `form:"attestationObject" validate:"required,base64rawurl,min=100,max=5000"`
	ClientDataJson          string `form:"clientDataJson" validate:"required,base64rawurl,min=100,max=500"`
}

func NewApp() (*App, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	origin := os.Getenv("ORIGIN")
	if len(origin) == 0 {
		return nil, errors.New("could not find env for origin")
	}
	rpId := os.Getenv("RP_ID")
	if len(rpId) == 0 {
		return nil, errors.New("could not find env for rp id")
	}

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not find env for mysql uri")
	}
	redisHost := os.Getenv("REDIS_HOST")
	if len(redisHost) == 0 {
		return nil, errors.New("could not find env for redis host")
	}
	redisPw := os.Getenv("REDIS_PW")
	if len(redisPw) == 0 {
		return nil, errors.New("could not find env for redis pw")
	}

	driver, err := sql.Open(dialect.MySQL, mysqlUri)
	if err != nil {
		return nil, err
	}
	db := driver.DB()
	db.SetMaxIdleConns(ENT_MAX_CONN)
	db.SetMaxOpenConns(ENT_MAX_CONN)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	ent := ent.NewClient(ent.Driver(driver))

	redis := redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: redisPw,
	})
	if err := redis.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	pasuki := pasuki2.NewPasuki2(ent.Passkey, redis, origin, rpId)
	validator := validator.New()

	return &App{ent, pasuki, validator}, nil
}

func (a *App) Close() error {
	return a.ent.Close()
}

func (a *App) bind(ctx echo.Context, target any) error {
	if err := ctx.Bind(target); err != nil {
		return err
	}

	if err := a.validator.Struct(target); err != nil {
		return err
	}

	return nil
}

func (a *App) RegisterStart(ctx echo.Context) error {
	form := RegisterStartRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	u, err := a.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldName,
			user.FieldLoginMethod,
		).
		Where(user.Email(form.Email)).
		Only(c)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user email")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if u.LoginMethod != user.LoginMethodPasskey {
		err := a.ent.User.UpdateOneID(u.ID).
			SetLoginMethod(user.LoginMethodPasskey).
			Exec(c)
		if err != nil {
			ctx.Logger().Error(err)
			return echo.ErrInternalServerError
		}
	}

	op, err := a.pasuki.RegisterStart(c, pasuki2.RegisterStartParams{
		UserId: u.ID,
		Email:  form.Email,
		Name:   u.Name,
	})

	return ctx.JSON(http.StatusOK, op)
}

func (a *App) RegisterFinish(ctx echo.Context) error {
	form := RegisterFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	u, err := a.ent.User.Query().
		Select(user.FieldID).
		Where(user.Email(form.Email)).
		Only(c)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user email")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	r := a.pasuki.RegisterFinish(c, pasuki2.RegisterFinishParams{
		Email:             form.Email,
		UserId:            u.ID,
		Id:                form.Id,
		Type:              form.Type,
		AttestationObject: form.AttestationObject,
		ClientDataJson:    form.ClientDataJson,
	})
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}

	ctx.Logger().Info(r.ClientData)
	ctx.Logger().Info(r.AttestationObject)

	return ctx.NoContent(http.StatusOK)
}
