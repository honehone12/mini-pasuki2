package app

import (
	"context"
	"errors"
	"mini-pasuki2/binid"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/passkey"
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

type Request struct {
	Email string `form:"email" validate:"required,email,max=256"`
}

type RegisterRequest struct {
	Request
	Name string `form:"name" validate:"required,max=256"`
}

type RegisterStartRequest = RegisterRequest

type RegisterFinishRequest struct {
	RegisterRequest
	// (!) this is passkey credential id, not our database id
	Id                      string `form:"id" validate:"required,base64rawurl,min=22"`
	Type                    string `form:"type" validate:"required,eq=public-key"`
	AuthenticatorAttachment string `form:"authenticatorAttachment" validata:"omitempty,oneof=platform cross-platform"`
	AttestationObject       string `form:"attestationObject" validate:"required,base64rawurl,min=100,max=5000"`
	ClientDataJson          string `form:"clientDataJson" validate:"required,base64rawurl,min=100,max=500"`
}

type VerifyStartRequest = Request

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

func (*App) rollback(tx *ent.Tx, original error) error {
	if err := tx.Rollback(); err != nil {
		return errors.Join(original, err)
	}

	return original
}

func (a *App) getUser(ctx context.Context, email string) (*ent.User, error) {
	u, err := a.ent.User.Query().
		Select(
			user.FieldID,
			user.FieldLoginMethod,
		).
		Where(
			user.Email(email),
			user.DeletedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	if u.LoginMethod != user.LoginMethodPasskey {
		return nil, errors.New("login method is not passkey")
	}

	return u, nil
}

func (a *App) RegisterStart(ctx echo.Context) error {
	form := RegisterStartRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	r := a.pasuki.RegisterStart(ctx.Request().Context(), form.Email, form.Name)
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}

	return ctx.JSON(http.StatusOK, r.Options)
}

func (a *App) RegisterFinish(ctx echo.Context) error {
	form := RegisterFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	p := pasuki2.RegisterFinishParams{
		Email:             form.Email,
		Name:              form.Name,
		Id:                form.Id,
		Type:              form.Type,
		AttestationObject: form.AttestationObject,
		ClientDataJson:    form.ClientDataJson,
	}
	r := a.pasuki.RegisterFinish(c, &p)
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}

	passId, err := binid.NewSequential()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	userId, err := binid.NewSequential()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	tx, err := a.ent.Tx(c)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	err = tx.User.Create().
		SetID(userId).
		SetName(form.Name).
		SetEmail(form.Email).
		Exec(c)
	if err != nil {
		err = a.rollback(tx, err)
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}
	err = tx.Passkey.Create().
		SetID(passId).
		SetOrigin(r.ClientData.Origin).
		SetCrossOrigin(r.ClientData.CrossOrigin).
		SetTopOrigin(r.ClientData.TopOrigin).
		SetAttestationFmt(passkey.AttestationFmt(r.AttestationObject.Fmt)).
		SetBackupEligibilityBit(r.AttestationObject.BeBit).
		SetBackupStateBit(r.AttestationObject.BsBit).
		SetSignCount(r.AttestationObject.SignCount).
		SetAaguid(r.AttestationObject.Aaguid).
		SetCredentialID(r.AttestationObject.CredentialId).
		SetPublicKey(r.AttestationObject.CredentialPublicKey).
		SetExtensionBit(r.AttestationObject.ExtBit).
		SetUserID(userId).
		Exec(c)
	if err != nil {
		err = a.rollback(tx, err)
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit(); err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	return ctx.NoContent(http.StatusOK)
}

func (a *App) VerifyStart(ctx echo.Context) error {
	form := VerifyStartRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()

	u, err := a.getUser(c, form.Email)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("could not find user email")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	r := a.pasuki.VerifyStart(c, u.ID, form.Email)
	if r.ValidationErr != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}
	if r.SystemErr != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	return ctx.JSON(http.StatusOK, r.Options)
}
