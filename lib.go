package main

import (
	"mini-pasuki2/app"
	"net/url"

	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)

	app, err := app.NewApp()
	if err != nil {
		echo.Logger.Fatal(err)
	}
	defer app.Close()

	uiUrl, err := url.Parse("http://localhost:3000")
	if err != nil {
		echo.Logger.Fatal(err)
	}
	balancer := echo4middleware.NewRoundRobinBalancer(
		[]*echo4middleware.ProxyTarget{{
			Name: "ui",
			URL:  uiUrl,
		}})

	echo.POST("/api/passkey/register/start", app.RegisterStart)
	echo.POST("/api/passkey/register/finish", app.RegisterFinish)
	echo.POST("/api/passkey/verify/start", app.VerifyStart)

	echo.Group("/*", echo4middleware.Proxy(balancer))

	if err := echo.Start("localhost:8082"); err != nil {
		echo.Logger.Fatal(err)
	}
}
