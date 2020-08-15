package v2

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/resources"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const unknownTokenTypeErrTemplate = "'%s' is not a valid token type"

var jwtSigningMethod = jwt.SigningMethodHS256

// Authorizer provides an interface for creating auth tokens and checking their permissions
type Authorizer interface {
	// CreateUserToken creates a token for the given user.
	// Setting expirationDate to 0 will create a token that does not expire.
	CreateUserToken(userId primitive.ObjectID, expirationDate int64) (string, error)
	// CreateServiceToken creates a token for the given owner with the provided permissions.
	// Setting expirationDate to 0 will create a token that does not expire.
	CreateServiceToken(owner string, allowedResources []UniformResourceIdentifier, timeToLive int64) (string, error)
	// GetAuthorizedResources returns what resources from urisToCheck the given token can access.
	// Will return ErrInvalidToken if the provided token is invalid.
	GetAuthorizedResources(token string, urisToCheck []UniformResourceIdentifier) ([]UniformResourceIdentifier, error)
	// WithAuthMiddleware wraps the given operation handler with authorization middleware
	WithAuthMiddleware(router resources.RouterResource, handler gin.HandlerFunc) gin.HandlerFunc
}

func NewAuthorizer(provider utils.TimeProvider, env *environment.Env, logger *zap.Logger) Authorizer {
	return &authorizer{
		timeProvider: provider,
		env:          env,
		logger:       logger,
	}
}

type authorizer struct {
	timeProvider utils.TimeProvider
	env          *environment.Env
	logger       *zap.Logger
}

func (a *authorizer) CreateUserToken(userId primitive.ObjectID, expirationDate int64) (string, error) {
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwtSigningMethod, TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        userId.Hex(),
			IssuedAt:  timestamp,
			ExpiresAt: expirationDate,
		},
		TokenType: user,
	})

	return token.SignedString([]byte(a.env.Get(environment.JWTSecret)))
}

func (a *authorizer) CreateServiceToken(owner string, allowedResources []UniformResourceIdentifier, expirationDate int64) (string, error) {
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwtSigningMethod, TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        owner,
			IssuedAt:  timestamp,
			ExpiresAt: expirationDate,
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
		return nil, errors.Wrap(ErrInvalidToken, err.Error())
	}

	err = verifyTokenType(claims.TokenType)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidToken, err.Error())
	}

	// filtering for resources the token has access to
	var allowedResources []UniformResourceIdentifier
	for _, resource := range claims.AllowedResources {
		if resource.isSubsetOfAtLeastOne(urisToCheck) {
			allowedResources = append(allowedResources, resource)
		}
	}

	return allowedResources, nil
}

func (a *authorizer) WithAuthMiddleware(router resources.RouterResource, operationHandler gin.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, err := router.GetAuthToken(ctx)
		if err != nil || token == "" {
			a.logger.Debug("empty token", zap.Error(err))
			router.HandleUnauthorized(ctx)
			return
		}

		uri := NewUriFromRequest(router, operationHandler, ctx)
		authorized, err := a.GetAuthorizedResources(token, []UniformResourceIdentifier{uri})
		if err != nil {
			a.logger.Debug("could not retrieve authorized resources for token", zap.Error(err))
			router.HandleUnauthorized(ctx)
			return
		}

		if len(authorized) == 0 {
			// TODO: implement unit test for this branch.
			// Blocked as GetAuthorizedResources does not actually
			// check what resources the token can access.
			router.HandleUnauthorized(ctx)
			return
		}

		operationHandler(ctx)
		return
	}
}

func verifyTokenType(tokenType TokenType) error {
	switch tokenType {
	case user:
	case service:
	default:
		return errors.Errorf(unknownTokenTypeErrTemplate, tokenType)
	}
	return nil
}
