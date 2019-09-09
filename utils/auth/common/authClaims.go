package common

import (
	"github.com/dgrijalva/jwt-go"
)

// AuthClaims is the model for the claims in the JWT token
type AuthClaims struct {
	jwt.StandardClaims
	AuthLevel AuthLevel `json:"auth_level"`
}
