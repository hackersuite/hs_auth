package v2

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Authorizer interface {
	CreateUserToken(userId primitive.ObjectID, timeToLive int64) (string, error)
	CreateServiceToken(owner string, allowedResources []UniformResourceIdentifier, timeToLive int64) (string, error)
	GetAuthorizedResources(token string, urisToCheck []UniformResourceIdentifier) ([]UniformResourceIdentifier, error)
}

func NewAuthorizer(provider utils.TimeProvider, env *environment.Env) Authorizer {
	return &authorizer{
		timeProvider: provider,
		env:          env,
	}
}

type authorizer struct {
	timeProvider utils.TimeProvider
	env          *environment.Env
}

func (a *authorizer) CreateUserToken(userId primitive.ObjectID, timeToLive int64) (string, error) {
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        userId.Hex(),
			IssuedAt:  timestamp,
			ExpiresAt: timestamp + timeToLive,
		},
		TokenType: user,
	})

	return token.SignedString([]byte(a.env.Get(environment.JWTSecret)))
}

func (a *authorizer) CreateServiceToken(owner string, allowedResources []UniformResourceIdentifier, timeToLive int64) (string, error) {
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        owner,
			IssuedAt:  timestamp,
			ExpiresAt: timestamp + timeToLive,
		},
		TokenType:        service,
		AllowedResources: allowedResources,
	})

	return token.SignedString([]byte(a.env.Get(environment.JWTSecret)))
}

func (a *authorizer) GetAuthorizedResources(token string, urisToCheck []UniformResourceIdentifier) ([]UniformResourceIdentifier, error) {
	var claims TokenClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(a.env.Get(environment.JWTSecret)), nil
	})
	if err != nil {
		return nil, err
	}

	err = verifyTokenType(claims.TokenType)
	if err != nil {
		return nil, err
	}

	// TODO: implement filtering for resources the token does not have access to
	return urisToCheck, nil
}

func verifyTokenType(tokenType TokenType) error {
	switch tokenType {
	case user:
	case service:
	default:
		return ErrInvalidTokenType
	}
	return nil
}
