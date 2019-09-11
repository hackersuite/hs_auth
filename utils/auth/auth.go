package auth

import (
	"errors"
	"math/rand"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

const lettersForEmailToken = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"

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

// GetHashForPassword generates a hash for the given password with the given salt
func GetHashForPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
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

// NewEmailToken creates a random email token of given length
func NewEmailToken(length int) string {
	token := make([]byte, length)
	for i := range token {
		token[i] = lettersForEmailToken[rand.Int63()%int64(len(lettersForEmailToken))]
	}
	return string(token)
}

// CompareHashAndPassword compares the hash to the password.
// If they both represent the same string, returns nill.
// Returns an error otherwise
func CompareHashAndPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
