package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mini-pasuki2/binid"
	"mini-pasuki2/challenge"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/passkey"
	"mini-pasuki2/ent/user"
	"mini-pasuki2/form"
	"mini-pasuki2/pasuki2"
	"net/http"
	"os"
	"time"

	"entgo.io/ent/dialect"

	"entgo.io/ent/dialect/sql"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	_ "github.com/go-sql-driver/mysql"
)

const ENT_MAX_CONN = 3

const (
	__REDIS_REGISTRATION_CHALLENGE_KEY = "REGCHAL"
	__REDIS_VERIFY_CHALLENGE_KEY       = "VERCHAL"
)
const __SESSION_PLACEHOLDER = "USE_COOKIE_SESSION_VALUE"

type App struct {
	ent       *ent.Client
	redis     *redis.Client
	validator *validator.Validate

	origin             string
	relyingParty       string
	relyingPartyIdHash []byte
}

func NewApp() (*App, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	origin := os.Getenv("ORIGIN")
	if len(origin) == 0 {
		return nil, errors.New("could not find env for origin")
	}
	rp := os.Getenv("RP_NAME")
	if len(rp) == 0 {
		return nil, errors.New("could not find env for rp name")
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

	validator := validator.New()
	rpIdHash := sha256.Sum256([]byte(rpId))

	return &App{
		ent,
		redis,
		validator,
		origin,
		rp,
		rpIdHash[:],
	}, nil
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

func (a *App) RegisterStart(ctx echo.Context) error {
	form := form.RegisterStartRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	chal, err := challenge.Gen()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}
	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, form.Email)
	err = a.redis.SetArgs(
		ctx.Request().Context(),
		key,
		encChal,
		redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * pasuki2.DEFAULT_TIME_OUT_MIL,
		},
	).Err()
	if errors.Is(err, redis.Nil) {
		ctx.Logger().Warn("challenge already exists")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	op := pasuki2.RegisterStart(&form, a.relyingParty, encChal)

	return ctx.JSON(http.StatusOK, op)
}

func (a *App) RegisterFinish(ctx echo.Context) error {
	form := form.RegisterFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()

	key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, form.Email)
	chal, err := a.redis.GetDel(c, key).Result()
	if errors.Is(err, redis.Nil) {
		ctx.Logger().Warn("register challenge not found")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	r := pasuki2.RegisterFinish(&form, a.relyingPartyIdHash, a.origin, chal)
	if r.Error != nil {
		ctx.Logger().Warn(r.Error)
		return echo.ErrBadRequest
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
	chal, err := challenge.Gen()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}
	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%x", __REDIS_VERIFY_CHALLENGE_KEY, []byte(__SESSION_PLACEHOLDER))
	err = a.redis.SetArgs(
		ctx.Request().Context(),
		key,
		encChal,
		redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * pasuki2.DEFAULT_TIME_OUT_MIL,
		},
	).Err()
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	op := pasuki2.VerifyStart([]byte(__SESSION_PLACEHOLDER), encChal)

	return ctx.JSON(http.StatusOK, op)
}

func (a *App) VerifyFinish(ctx echo.Context) error {
	form := form.VerifyFinishRequest{}

	if err := a.bind(ctx, &form); err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	credId, err := base64.RawURLEncoding.DecodeString(form.Id)
	if err != nil {
		ctx.Logger().Warn(err)
		return echo.ErrBadRequest
	}

	c := ctx.Request().Context()

	passK, err := a.ent.Passkey.Query().
		Select(
			passkey.FieldSignCount,
			passkey.FieldPublicKey,
		).
		Where(
			passkey.CredentialID(credId),
			passkey.DeletedAtIsNil(),
		).
		Only(c)
	if ent.IsNotFound(err) {
		ctx.Logger().Warn("passkey not found")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	key := fmt.Sprintf("%s:%x", __REDIS_VERIFY_CHALLENGE_KEY, []byte(__SESSION_PLACEHOLDER))
	encChal, err := a.redis.GetDel(c, key).Result()
	if errors.Is(err, redis.Nil) {
		ctx.Logger().Warn("verify challenge not found")
		return echo.ErrBadRequest
	} else if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	p := pasuki2.VerifyFinishParams{
		Session:            []byte(__SESSION_PLACEHOLDER),
		PublicKey:          passK.PublicKey,
		RelyingPartyIdHash: a.relyingPartyIdHash,
		Origin:             a.origin,
		Challenge:          encChal,
		CurrentCount:       passK.SignCount,
	}
	r := pasuki2.VerifyFinish(&form, &p)
	if r.SystemErr != nil {
		ctx.Logger().Error(r.SystemErr)
		return echo.ErrInternalServerError
	}
	if r.ValidationErr != nil {
		ctx.Logger().Warn(r.ValidationErr)
		return echo.ErrBadRequest
	}

	err = a.ent.Passkey.UpdateOneID(passK.ID).
		SetSignCount(r.AuthData.SignCount).
		SetBackupEligibilityBit(r.AuthData.BeBit).
		SetBackupStateBit(r.AuthData.BsBit).
		Exec(c)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.ErrInternalServerError
	}

	return ctx.NoContent(http.StatusOK)
}
