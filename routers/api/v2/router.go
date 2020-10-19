package v2

import (
	common2 "github.com/unicsmcr/hs_auth/routers/common"
	"net/http"

	"github.com/gin-gonic/gin"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"go.uber.org/zap"
)

const authTokenHeader = "Authorization"

type APIV2Router interface {
	models.Router
	Login(ctx *gin.Context)
	Register(ctx *gin.Context)
	GetUsers(ctx *gin.Context)
	GetUser(ctx *gin.Context)
	SetRole(ctx *gin.Context)
	SetSpecialPermissions(ctx *gin.Context)
	SetPassword(ctx *gin.Context)
	GetPasswordResetEmail(ctx *gin.Context)
	ResendEmailVerification(ctx *gin.Context)
	VerifyEmail(ctx *gin.Context)
	GetAuthorizedResources(ctx *gin.Context)
	CreateServiceToken(ctx *gin.Context)
	InvalidateServiceToken(ctx *gin.Context)
	CreateTeam(ctx *gin.Context)
	GetTeams(ctx *gin.Context)
	GetTeam(ctx *gin.Context)
	SetTeam(ctx *gin.Context)
	RemoveFromTeam(ctx *gin.Context)
}

type apiV2Router struct {
	models.BaseRouter
	logger       *zap.Logger
	cfg          *config.AppConfig
	authorizer   v2.Authorizer
	userService  services.UserService
	tokenService services.TokenService
	teamService  services.TeamService
	emailService services.EmailServiceV2
	timeProvider utils.TimeProvider
}

func NewAPIV2Router(logger *zap.Logger, cfg *config.AppConfig, authorizer v2.Authorizer,
	userService services.UserService, teamService services.TeamService, tokenService services.TokenService,
	emailService services.EmailServiceV2, timeProvider utils.TimeProvider) APIV2Router {
	return &apiV2Router{
		logger:       logger,
		cfg:          cfg,
		authorizer:   authorizer,
		userService:  userService,
		tokenService: tokenService,
		teamService:  teamService,
		emailService: emailService,
		timeProvider: timeProvider,
	}
}

func (r *apiV2Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	usersGroup := routerGroup.Group("/users")
	usersGroup.GET("/", r.authorizer.WithAuthMiddleware(r, r.GetUsers))
	usersGroup.GET("/:id", r.authorizer.WithAuthMiddleware(r, r.GetUser))
	usersGroup.PUT("/:id/team", r.authorizer.WithAuthMiddleware(r, r.SetTeam))
	usersGroup.DELETE("/:id/team", r.authorizer.WithAuthMiddleware(r, r.RemoveFromTeam))
	usersGroup.POST("/", r.Register)
	usersGroup.POST("/login", r.Login)
	usersGroup.PUT("/:id/role", r.authorizer.WithAuthMiddleware(r, r.SetRole))
	usersGroup.PUT("/:id/permissions", r.authorizer.WithAuthMiddleware(r, r.SetSpecialPermissions))
	usersGroup.PUT("/:id/password", r.authorizer.WithAuthMiddleware(r, r.SetPassword))
	usersGroup.GET("/:id/password/resetEmail", r.GetPasswordResetEmail)
	usersGroup.PUT("/:id/email/verify", r.authorizer.WithAuthMiddleware(r, r.VerifyEmail))
	usersGroup.GET("/:id/email/verify", r.authorizer.WithAuthMiddleware(r, r.ResendEmailVerification))

	tokensGroup := routerGroup.Group("/tokens")
	tokensGroup.GET("/resources/authorized", r.authorizer.WithAuthMiddleware(r, r.GetAuthorizedResources))
	tokensGroup.POST("/service", r.authorizer.WithAuthMiddleware(r, r.CreateServiceToken))
	tokensGroup.DELETE("/service/:id", r.authorizer.WithAuthMiddleware(r, r.InvalidateServiceToken))

	teamsGroups := routerGroup.Group("/teams")
	teamsGroups.GET("/", r.authorizer.WithAuthMiddleware(r, r.GetTeams))
	teamsGroups.GET("/:id", r.authorizer.WithAuthMiddleware(r, r.GetTeam))
	teamsGroups.POST("/", r.authorizer.WithAuthMiddleware(r, r.CreateTeam))
}

func (r *apiV2Router) GetResourcePath() string {
	return common2.ApiV2ResourcePath
}

func (r *apiV2Router) GetAuthToken(ctx *gin.Context) string {
	return ctx.GetHeader(authTokenHeader)
}

func (r *apiV2Router) HandleUnauthorized(ctx *gin.Context) {
	models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this operation")
}
