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

var EXPIRATION_TIME = time.Now().Add(time.Minute * 5)
var TOKEN_KEY = []byte(os.Getenv("JWT_TOKEN"))

func (h AuthHandler) HandleLogin(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	expectedPassword, ok := users[email]

	if !ok || expectedPassword != password {
		log.Println("passwords didnt match")
		return c.NoContent(http.StatusUnauthorized)
	}

	expiryTime := EXPIRATION_TIME
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiryTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString(TOKEN_KEY)
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

func (h AuthHandler) HandleRefreshToken(c echo.Context) error {
	tkn, claims, err := getTokenFromCookie(c, "token")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	if !tkn.Valid {
		return c.NoContent(http.StatusUnauthorized)
	}

	if time.Until(time.Unix(claims.ExpiresAt, 0)) > 30*time.Second {
		return c.NoContent(http.StatusBadRequest)
	}

	expirationTime := EXPIRATION_TIME
	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(TOKEN_KEY)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	c.SetCookie(&http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expirationTime,
	})

	return c.NoContent(http.StatusAccepted)
}

func (h AuthHandler) HandleLogout(c echo.Context) error {
	_, claims, err := getTokenFromCookie(c, "token")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	expirationTime := time.Now()
	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(TOKEN_KEY)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	c.SetCookie(&http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expirationTime,
	})

	return c.Redirect(http.StatusAccepted, "/login")

}

func (h AuthHandler) HandleProtectedRoute(c echo.Context) error {
	tkn, claims, err := getTokenFromCookie(c, "token")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	if !tkn.Valid {
		return c.NoContent(http.StatusUnauthorized)
	}

	return c.String(http.StatusOK, fmt.Sprintf("Hello %s", claims.Email))
}

func getTokenFromCookie(c echo.Context, cname string) (*jwt.Token, *Claims, error) {
	cookie, err := c.Cookie(cname)
	if err != nil {
		fmt.Println("cookie err", err)
		return nil, nil, err
	}

	tokenStr := cookie.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return TOKEN_KEY, nil
	})

	return tkn, claims, err
}
