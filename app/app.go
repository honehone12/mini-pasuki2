package app

import (
	"context"
	"errors"
	"mini-pasuki2/binid"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/passkey"
	"mini-pasuki2/ent/user"
	"mini-pasuki2/form"
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

const __SESSION_PLACEHOLDER = "use-cookie-session-value"

type App struct {
	ent       *ent.Client
	pasuki    *pasuki2.Pasuki2
	validator *validator.Validate
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

func rollback(tx *ent.Tx, original error) error {
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
	form := form.RegisterStartRequest{}

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
	form := form.RegisterFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()
	r := a.pasuki.RegisterFinish(c, &form)
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
		SetLoginMethod(user.LoginMethodPasskey).
		Exec(c)
	if err != nil {
		err = rollback(tx, err)
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}
	err = tx.Passkey.Create().
		SetID(passId).
		SetOrigin(r.ClientData.Origin).
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
		err = rollback(tx, err)
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
	op, err := a.pasuki.VerifyStart(
		ctx.Request().Context(),
		[]byte(__SESSION_PLACEHOLDER),
	)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrInternalServerError
	}

	return ctx.JSON(http.StatusOK, op)
}

func (a *App) VerifyFinish(ctx echo.Context) error {
	form := form.VerifyFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	r := a.pasuki.VerifyFinish(
		ctx.Request().Context(),
		&form,
		[]byte(__SESSION_PLACEHOLDER),
	)
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	ctx.Logger().Infof("%#v", r.ClientData)
	ctx.Logger().Infof("%#v", r.AuthData)

	return ctx.NoContent(http.StatusOK)
}
