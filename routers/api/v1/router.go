package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.uber.org/zap"
)

const authHeaderName = "Authorization"

// APIV1Router is the router for v1 of the API
type APIV1Router interface {
	models.Router
	GetUsers(*gin.Context)
	Login(*gin.Context)
	Verify(*gin.Context)
	GetMe(*gin.Context)
	PutMe(*gin.Context)
	Register(*gin.Context)
	VerifyEmail(*gin.Context)
	AuthLevelVerifierFactory(level authlevels.AuthLevel) func(*gin.Context)
	CreateTeam(*gin.Context)
}

type apiV1Router struct {
	models.BaseRouter
	logger       *zap.Logger
	cfg          *config.AppConfig
	userService  services.UserService
	emailService services.EmailService
	teamService  services.TeamService
	env          *environment.Env
}

// NewAPIV1Router creates a APIV1Router
func NewAPIV1Router(logger *zap.Logger, cfg *config.AppConfig, userService services.UserService, emailService services.EmailService, teamService services.TeamService, env *environment.Env) APIV1Router {
	return &apiV1Router{
		logger:       logger,
		cfg:          cfg,
		userService:  userService,
		emailService: emailService,
		teamService:  teamService,
		env:          env,
	}
}

// RegisterRoutes registers all of the API's (v1) routes to the given router group
func (r *apiV1Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	isAtLeastApplicant := r.AuthLevelVerifierFactory(authlevels.Applicant)
	isAtLeastOrganizer := r.AuthLevelVerifierFactory(authlevels.Organizer)

	usersGroup := routerGroup.Group("/users")
	usersGroup.GET("/", isAtLeastOrganizer, r.GetUsers)
	usersGroup.POST("/", r.Register)
	usersGroup.POST("/login", r.Login)
	usersGroup.GET("/email/verify", r.VerifyEmail)
	usersGroup.GET("/verify", isAtLeastApplicant, r.Verify)
	usersGroup.GET("/me", isAtLeastApplicant, r.GetMe)
	usersGroup.PUT("/me", isAtLeastApplicant, r.PutMe)

	teamsGroup := routerGroup.Group("/teams")
	teamsGroup.POST("/", isAtLeastApplicant, r.CreateTeam)
}
