package main

import (
	"mini-pasuki2/app"

	"github.com/joho/godotenv"
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)

	if err := godotenv.Load(); err != nil {
		echo.Logger.Fatal(err)
	}

	app, err := app.NewApp()
	if err != nil {
		echo.Logger.Fatal(err)
	}

	echo.Use(echo4middleware.CORSWithConfig(echo4middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000"},
	}))

	echo.POST("/api/passkey/register/start", app.RegisterStart)

	if err := echo.Start("localhost:8081"); err != nil {
		echo.Logger.Fatal(err)
	}
}
