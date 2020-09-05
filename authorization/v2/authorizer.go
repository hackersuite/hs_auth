package v2

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/resources"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
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
	// CreateServiceToken creates a token with the given permissions.
	// Setting expirationDate to 0 will create a token that does not expire.
	CreateServiceToken(ctx context.Context, userId primitive.ObjectID, allowedResources []UniformResourceIdentifier, expirationDate int64) (string, error)
	// InvalidateServiceToken invalidates a token with the given ID
	InvalidateServiceToken(ctx context.Context, tokenId string) error
	// GetAuthorizedResources returns what resources from urisToCheck the given token can access.
	// Will return ErrInvalidToken if the provided token is invalid.
	GetAuthorizedResources(token string, urisToCheck []UniformResourceIdentifier) ([]UniformResourceIdentifier, error)
	// WithAuthMiddleware wraps the given operation handler with authorization middleware
	WithAuthMiddleware(router resources.RouterResource, handler gin.HandlerFunc) gin.HandlerFunc
	// GetUserIdFromToken extracts the user id from user tokens
	GetUserIdFromToken(token string) (primitive.ObjectID, error)
	// GetTokenTypeFromToken extracts the token type from the given token
	GetTokenTypeFromToken(token string) (TokenType, error)
}

func NewAuthorizer(provider utils.TimeProvider, env *environment.Env, logger *zap.Logger, tokenService services.TokenService) Authorizer {
	return &authorizer{
		timeProvider: provider,
		env:          env,
		logger:       logger,
		tokenService: tokenService,
	}
}

type authorizer struct {
	timeProvider utils.TimeProvider
	env          *environment.Env
	logger       *zap.Logger
	tokenService services.TokenService
}

func (a *authorizer) CreateUserToken(userId primitive.ObjectID, expirationDate int64) (string, error) {
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwtSigningMethod, tokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        userId.Hex(),
			IssuedAt:  timestamp,
			ExpiresAt: expirationDate,
		},
		TokenType: User,
	})

	return token.SignedString([]byte(a.env.Get(environment.JWTSecret)))
}

func (a *authorizer) CreateServiceToken(ctx context.Context, userId primitive.ObjectID, allowedResources []UniformResourceIdentifier, expirationDate int64) (string, error) {
	tokenId := primitive.NewObjectID()
	timestamp := a.timeProvider.Now().Unix()
	token := jwt.NewWithClaims(jwtSigningMethod, tokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        tokenId.Hex(),
			IssuedAt:  timestamp,
			ExpiresAt: expirationDate,
		},
		TokenType:        Service,
		AllowedResources: allowedResources,
	})

	// Store the service token in the database
	_, err := a.tokenService.CreateServiceToken(ctx, userId.Hex(), token.Raw)
	if err != nil {
		return "", errors.Wrap(ErrPersistToken, err.Error())
	}

	return token.SignedString([]byte(a.env.Get(environment.JWTSecret)))
}

func (a *authorizer) InvalidateServiceToken(ctx context.Context, tokenId string) error {
	return a.tokenService.DeleteServiceToken(ctx, tokenId)
}

func (a *authorizer) GetAuthorizedResources(token string, urisToCheck []UniformResourceIdentifier) ([]UniformResourceIdentifier, error) {
	claims, err := getTokenClaims(token, a.env.Get(environment.JWTSecret))
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
		token := router.GetAuthToken(ctx)
		if token == "" {
			a.logger.Debug("empty token")
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
			router.HandleUnauthorized(ctx)
			return
		}

		operationHandler(ctx)
		return
	}
}

func (a *authorizer) GetUserIdFromToken(token string) (primitive.ObjectID, error) {
	claims, err := getTokenClaims(token, a.env.Get(environment.JWTSecret))
	if err != nil {
		return primitive.ObjectID{}, errors.Wrap(ErrInvalidToken, err.Error())
	}

	if claims.TokenType != User {
		return primitive.ObjectID{}, errors.Wrap(ErrInvalidTokenType, fmt.Sprintf("user id can only be "+
			"extracted from tokens of type %s", User))
	}

	userId, err := primitive.ObjectIDFromHex(claims.StandardClaims.Id)
	if err != nil {
		return primitive.ObjectID{}, errors.Wrap(ErrInvalidToken, errors.Wrap(err, "malformed user id").Error())
	}
	return userId, nil
}

func (a *authorizer) GetTokenTypeFromToken(token string) (TokenType, error) {
	claims, err := getTokenClaims(token, a.env.Get(environment.JWTSecret))
	if err != nil {
		return "", errors.Wrap(ErrInvalidToken, err.Error())
	}

	err = verifyTokenType(claims.TokenType)
	if err != nil {
		return "", errors.Wrap(ErrInvalidToken, err.Error())
	}

	return claims.TokenType, nil
}

func getTokenClaims(token string, jwtSecret string) (tokenClaims, error) {
	var claims tokenClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return tokenClaims{}, errors.Wrap(err, "could not parse token claims")
	}
	return claims, nil
}

func verifyTokenType(tokenType TokenType) error {
	switch tokenType {
	case User:
	case Service:
	default:
		return errors.Errorf(unknownTokenTypeErrTemplate, tokenType)
	}
	return nil
}
