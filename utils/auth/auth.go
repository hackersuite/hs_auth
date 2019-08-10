package auth

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
)

// NewJWT creates a new JWT token for the specified user with the specified secret
func NewJWT(user entities.User, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT token secret undefined")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":        user.ID,
		"auth_level": user.AuthLevel,
	})

	fmt.Println(secret)

	return token.SignedString(secret)
}
