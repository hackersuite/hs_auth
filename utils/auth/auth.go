package auth

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"golang.org/x/crypto/bcrypt"
)

// AuthHeaderName is the name of the header to be user to store auth tokens
const AuthHeaderName = "Authorization"

// TokenType represent an auth token type
type TokenType string

var (
	// Email is token type for email tokens
	Email TokenType = "email"
	// Auth is token type for auth tokens
	Auth TokenType = "auth"
)

// Claims is the model for the claims in the JWT token
type Claims struct {
	jwt.StandardClaims
	AuthLevel common.AuthLevel `json:"auth_level"`
	TokenType TokenType        `json:"token_type"`
}

// GetJWTClaims checks if the given token is a valid JWT with given secret
// and returns the claims inside the token. Returns nill if the token is invalid
func GetJWTClaims(token string, secret []byte) *Claims {
	var claims Claims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
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

// NewJWT creates a new JWT for the specified user with the specified secret
func NewJWT(user entities.User, timestamp int64, validityDuration int64, tokenType TokenType, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT secret undefined")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		StandardClaims: jwt.StandardClaims{
			Id:        user.ID.Hex(),
			IssuedAt:  timestamp,
			ExpiresAt: timestamp + validityDuration,
		},
		AuthLevel: user.AuthLevel,
		TokenType: tokenType,
	})

	return token.SignedString(secret)
}

// CompareHashAndPassword compares the hash to the password.
// If they both represent the same string, returns nill.
// Returns an error otherwise
func CompareHashAndPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
