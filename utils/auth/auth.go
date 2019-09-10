package auth

import (
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
)

// GetJWTClaims checks if the given token is a valid JWT with given secret
// and returns the claims inside the token. Returns nill if the token is invalid
func GetJWTClaims(token string, secret []byte) *common.AuthClaims {
	var claims common.AuthClaims
	parsedToken, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		return nil
	}

	userID, err := primitive.ObjectIDFromHex(claims.Id)
	if err != nil {
		return nil
	}
	expectedToken, err := NewJWT(entities.User{
		ID:        userID,
		AuthLevel: claims.AuthLevel,
	}, claims.IssuedAt, secret)
	if err != nil {
		return nil
	}

	if parsedToken.Raw != expectedToken {
		return nil
	}
	return &claims
}

// NewJWT creates a new JWT token for the specified user with the specified secret
func NewJWT(user entities.User, timestamp int64, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT token secret undefined")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &common.AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:       user.ID.Hex(),
			IssuedAt: timestamp,
		},
		AuthLevel: user.AuthLevel,
	})

	return token.SignedString(secret)
}
