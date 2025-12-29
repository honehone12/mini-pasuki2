package main

import (
	echo4 "github.com/labstack/echo/v4"
	echo4middleware "github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func run() {
	echo := echo4.New()
	echo.Use(echo4middleware.RequestLogger())
	echo.Logger.SetLevel(log.INFO)

	if err := echo.Start("localhost:8081"); err != nil {
		echo.Logger.Fatal(err)
	}
}
