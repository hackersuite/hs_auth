package v2

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
)

type TokenType string

const User TokenType = "user"
const Service TokenType = "service"

type tokenClaims struct {
	jwt.StandardClaims
	TokenType        `json:"token_type"`
	AllowedResources []common.UniformResourceIdentifier `json:"allowed_resources,omitempty"`
}
