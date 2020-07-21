package v2

import (
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

type APIV2Router interface {
	models.Router
	Login(ctx *gin.Context)
	GetUsers(ctx *gin.Context)
	GetAuthorizedResources(ctx *gin.Context)
}

type apiV2Router struct {
	models.BaseRouter
	logger *zap.Logger
	authorizer v2.Authorizer
}


func NewAPIV2Router(logger *zap.Logger, authorizer v2.Authorizer) APIV2Router {
	return &apiV2Router{
		logger: logger,
		authorizer: authorizer,
	}
}

func (r *apiV2Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	usersGroup := routerGroup.Group("/users")
	usersGroup.GET("/", r.buildAuthChecker("hs:hs_auth:api:v2:getUsers"), r.GetUsers)
	usersGroup.POST("/login", r.Login)

	tokensGroup := routerGroup.Group("/tokens")
	tokensGroup.GET("/resources/authorized", r.buildAuthChecker("hs:hs_auth:api:v2:getAuthorizedResources"), r.GetAuthorizedResources)
}

func (r *apiV2Router) Login(ctx *gin.Context) {
	token, err := r.authorizer.CreateUserToken(primitive.NewObjectIDFromTimestamp(time.Now()), int64(0))
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with creating authentication token")
		return
	}

	ctx.JSON(http.StatusOK, loginRes{
		Token: token,
	})
}

func (r *apiV2Router) GetUsers(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, getUsersRes{
		Users: []entities.User{
			{
				ID:            primitive.NewObjectID(),
				Name:          "Bob the Tester",
				Email:         "bob@test.com",
			},
			{
				ID:            primitive.NewObjectID(),
				Name:          "Rob the Tester",
				Email:         "rob@test.com",
			},
		},
	})
}

func (r *apiV2Router) GetAuthorizedResources(ctx *gin.Context) {
	var requestedUris []v2.UniformResourceIdentifier
	for _, uri := range strings.Split(ctx.Query("from"), ",") {
		requestedUris = append(requestedUris, v2.UniformResourceIdentifier(uri))
	}

	authorizedUris, err := r.authorizer.GetAuthorizedResources(extractAuthTokenFromCtx(ctx), requestedUris)
	if err != nil {
		switch errors.Cause(err) {
		case v2.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			handleUnauthorized(ctx)
		default:
			r.logger.Error("could not get authorized URIs", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, getAuthorizedResourcesRes{
		AuthorizedUris: authorizedUris,
	})
}

func (r *apiV2Router) buildAuthChecker(resources ...v2.UniformResourceIdentifier) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		authorizedResources, err := r.authorizer.GetAuthorizedResources(extractAuthTokenFromCtx(ctx), resources)
		if err != nil {
			switch errors.Cause(err) {
			case v2.ErrInvalidToken:
				r.logger.Debug("invalid token", zap.Error(err))
				handleUnauthorized(ctx)
			default:
				r.logger.Error("could not get authorized URIs", zap.Error(err))
				models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			}
			return
		}

		if len(authorizedResources) == 0 {
			handleUnauthorized(ctx)
			return
		}
	}
}

func handleUnauthorized(ctx *gin.Context) {
	models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this operation")
	ctx.Abort()
}

func extractAuthTokenFromCtx(ctx *gin.Context) string {
	return ctx.GetHeader("Authorization")
}