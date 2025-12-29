package main

import (
	"mini-pasuki2/app"
	"net/url"

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

	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}

	balancer := echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{{
			Name: "ui",
			URL:  uiUrl,
		}})
	echo.Use(echo4middleware.Proxy(balancer))

	echo.POST("/api/passkey/register/start", app.RegisterStart)

	if err := echo.Start("localhost:8082"); err != nil {
		echo.Logger.Fatal(err)
	}
}
