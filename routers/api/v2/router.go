package v2

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

const resourcePath = "hs:hs_auth:api:v2"
const authTokenHeader = "Authorization"

type APIV2Router interface {
	models.Router
	Login(ctx *gin.Context)
	Register(ctx *gin.Context)
	GetUsers(ctx *gin.Context)
	GetUser(ctx *gin.Context)
	GetAuthorizedResources(ctx *gin.Context)
	CreateServiceToken(ctx *gin.Context)
	CreateTeam(ctx *gin.Context)
	GetTeams(ctx *gin.Context)
	GetTeam(ctx *gin.Context)
}

type apiV2Router struct {
	models.BaseRouter
	logger       *zap.Logger
	cfg          *config.AppConfig
	authorizer   v2.Authorizer
	userService  services.UserService
	teamService  services.TeamService
	timeProvider utils.TimeProvider
}

func NewAPIV2Router(logger *zap.Logger, cfg *config.AppConfig, authorizer v2.Authorizer,
	userService services.UserService, teamService services.TeamService, timeProvider utils.TimeProvider) APIV2Router {
	return &apiV2Router{
		logger:       logger,
		cfg:          cfg,
		authorizer:   authorizer,
		userService:  userService,
		timeProvider: timeProvider,
		teamService:  teamService,
	}
}

func (r *apiV2Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	usersGroup := routerGroup.Group("/users")
	usersGroup.GET("/", r.authorizer.WithAuthMiddleware(r, r.GetUsers))
	usersGroup.GET("/:id", r.authorizer.WithAuthMiddleware(r, r.GetUser))
	usersGroup.POST("/", r.Register)
	usersGroup.POST("/login", r.Login)

	tokensGroup := routerGroup.Group("/tokens")
	tokensGroup.GET("/resources/authorized", r.authorizer.WithAuthMiddleware(r, r.GetAuthorizedResources))
	tokensGroup.POST("/service", r.authorizer.WithAuthMiddleware(r, r.CreateServiceToken))

	teamsGroups := routerGroup.Group("/teams")
	teamsGroups.GET("/", r.authorizer.WithAuthMiddleware(r, r.GetTeams))
	teamsGroups.GET("/:id", r.authorizer.WithAuthMiddleware(r, r.GetTeam))
	teamsGroups.POST("/", r.authorizer.WithAuthMiddleware(r, r.CreateTeam))
}

func (r *apiV2Router) GetResourcePath() string {
	return resourcePath
}

func (r *apiV2Router) GetAuthToken(ctx *gin.Context) string {
	return ctx.GetHeader(authTokenHeader)
}

func (r *apiV2Router) HandleUnauthorized(ctx *gin.Context) {
	models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this operation")
}

func (r *apiV2Router) GetAuthorizedResources(ctx *gin.Context) {
	var req struct {
		From string `form:"from"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		r.logger.Debug("could not parse get authorized resources request", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse request")
		return
	}

	// Remove the leading '[' and trailing ']' from the uri parameter
	req.From = req.From[1 : len(req.From)-1]
	rawUriList := strings.Split(req.From, ",")

	var requestedUris = make([]v2.UniformResourceIdentifier, len(rawUriList))
	for i, rawUri := range rawUriList {
		err := requestedUris[i].UnmarshalJSON([]byte(rawUri))
		if err != nil {
			r.logger.Debug(fmt.Sprintf("uri could not be parsed at index %d", i))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided uri could not be parsed")
			return
		}
	}

	token := r.GetAuthToken(ctx)
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
