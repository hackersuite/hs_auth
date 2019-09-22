package frontend

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

type FrontendRouter interface {
	models.Router
	LoginPage(*gin.Context)
	Login(*gin.Context)
}

type templateDataModel struct {
	Cfg  *config.AppConfig
	Data interface{}
}

type frontendRouter struct {
	models.BaseRouter
	logger       *zap.Logger
	cfg          *config.AppConfig
	env          *environment.Env
	userService  services.UserService
	emailService services.EmailService
}

func NewFrontendRouter(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env, userService services.UserService, emailService services.EmailService) FrontendRouter {
	return &frontendRouter{
		logger:       logger,
		cfg:          cfg,
		env:          env,
		userService:  userService,
		emailService: emailService,
	}
}

func (r *frontendRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("login", r.LoginPage)
	routerGroup.POST("login", r.Login)
}
