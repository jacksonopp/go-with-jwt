package handlers

import (
	"fmt"
	"go-with-jwt/cmd/web/auth"
	"go-with-jwt/internal/utils"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type Credentials struct {
	Email    string
	Password string
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

type AuthHandler struct{}

func (h AuthHandler) HandleLoginShow(c echo.Context) error {
	return utils.Render(c, auth.Login())
}

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

func (h AuthHandler) HandleLogin(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	expectedPassword, ok := users[email]

	if !ok || expectedPassword != password {
		log.Println("passwords didnt match")
		return c.NoContent(http.StatusUnauthorized)
	}

	expiryTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiryTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	key := os.Getenv("JWT_TOKEN")
	fmt.Println("LOOKIE HERE", key)

	tokenStr, err := token.SignedString([]byte(key))
	if err != nil {
		log.Println("Something went wrong...", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	c.SetCookie(&http.Cookie{
		Name:     "token",
		Value:    tokenStr,
		Expires:  expiryTime,
		HttpOnly: true,
	})

	return utils.Render(c, auth.Login())
}
