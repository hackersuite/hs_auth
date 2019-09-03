package auth

import (
	"errors"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
)

// NewJWT creates a new JWT token for the specified user with the specified secret
func NewJWT(user entities.User, timestamp int64, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT token secret undefined")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &common.AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:       user.ID.String(),
			IssuedAt: timestamp,
		},
		AuthLevel: user.AuthLevel,
	})

	return token.SignedString(secret)
}
