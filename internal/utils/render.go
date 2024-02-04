package utils

import (
	"github.com/a-h/templ"
	"github.com/labstack/echo/v4"
)

func Render(c echo.Context, comp templ.Component) error {
	return comp.Render(c.Request().Context(), c.Response().Writer)
}
