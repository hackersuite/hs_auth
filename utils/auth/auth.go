package auth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

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
	}, claims.IssuedAt, 0, claims.TokenType, secret)
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
func NewJWT(user entities.User, timestamp int64, validityDuration time.Duration, tokenType TokenType, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT token secret undefined")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		StandardClaims: jwt.StandardClaims{
			Id:       user.ID.Hex(),
			IssuedAt: timestamp,
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
