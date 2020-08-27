package v2

import "github.com/dgrijalva/jwt-go"

type TokenType string

const User TokenType = "user"
const Service TokenType = "service"

type TokenClaims struct {
	jwt.StandardClaims
	TokenType        `json:"token_type"`
	AllowedResources []UniformResourceIdentifier `json:"allowed_resources,omitempty"`
}
