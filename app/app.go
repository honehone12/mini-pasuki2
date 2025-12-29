package app

import (
	"errors"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/user"
	"mini-pasuki2/pasuki2"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"

	_ "github.com/go-sql-driver/mysql"
)

type App struct {
	ent       *ent.Client
	pasuki    *pasuki2.Pasuki2
	validator *validator.Validate
}

func NewApp() (*App, error) {
	// don't inject other than env
	// to prevent exposing sensitive info
	// just write within module for testing

	mysqlUri := os.Getenv("MYSQL_URI")
	if len(mysqlUri) == 0 {
		return nil, errors.New("could not find env for mysql uri")
	}

	ent, err := ent.Open(
		"mysql",
		mysqlUri,
		ent.Debug(),
	)
	if err != nil {
		return nil, err
	}

	pasuki := pasuki2.NewPasuki2(ent.Passkey)
	validator := validator.New()

	return &App{ent, pasuki, validator}, nil
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

type RegisterStartRequest struct {
	Email string `form:"string" validate:"required,email,max=256"`
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
		Id:    u.ID,
		Email: form.Email,
		Name:  u.Name,
	})

	return ctx.JSON(http.StatusOK, op)
}
