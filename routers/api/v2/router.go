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
	"time"
)

const resourcePath = "hs:hs_auth:api:v2"
const authTokenHeader = "Authorization"

type APIV2Router interface {
	models.Router
	Login(ctx *gin.Context)
	GetUsers(ctx *gin.Context)
	GetAuthorizedResources(ctx *gin.Context)
}

type apiV2Router struct {
	models.BaseRouter
	logger     *zap.Logger
	authorizer v2.Authorizer
}

func NewAPIV2Router(logger *zap.Logger, authorizer v2.Authorizer) APIV2Router {
	return &apiV2Router{
		logger:     logger,
		authorizer: authorizer,
	}
}

func (r *apiV2Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	usersGroup := routerGroup.Group("/users")
	usersGroup.GET("/", r.authorizer.WithAuthMiddleware(r, r.GetUsers))
	usersGroup.POST("/login", r.Login)

	tokensGroup := routerGroup.Group("/tokens")
	tokensGroup.GET("/resources/authorized/:id", r.authorizer.WithAuthMiddleware(r, r.GetAuthorizedResources))
}

func (r *apiV2Router) GetResourcePath() string {
	return resourcePath
}

func (r *apiV2Router) GetAuthToken(ctx *gin.Context) (string, error) {
	return ctx.GetHeader(authTokenHeader), nil
}

func (r *apiV2Router) HandleUnauthorized(ctx *gin.Context) {
	models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this operation")
	ctx.Abort()
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
				ID:    primitive.NewObjectID(),
				Name:  "Bob the Tester",
				Email: "bob@test.com",
			},
			{
				ID:    primitive.NewObjectID(),
				Name:  "Rob the Tester",
				Email: "rob@test.com",
			},
		},
	})
}

func (r *apiV2Router) GetAuthorizedResources(ctx *gin.Context) {
	// TODO: extract URIs from request, requires string -> URI mapper
	var requestedUris []v2.UniformResourceIdentifier

	token, err := r.GetAuthToken(ctx)
	if err != nil {
		r.logger.Debug("could not extract auth token", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	authorizedUris, err := r.authorizer.GetAuthorizedResources(token, requestedUris)
	if err != nil {
		switch errors.Cause(err) {
		case v2.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
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
