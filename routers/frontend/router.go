package frontend

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

type Router interface {
	models.Router
	LoginPage(*gin.Context)
	Login(*gin.Context)
	Logout(*gin.Context)
	RegisterPage(*gin.Context)
	Register(*gin.Context)
	ForgotPasswordPage(*gin.Context)
	ForgotPassword(*gin.Context)
	ResetPasswordPage(*gin.Context)
	ResetPassword(*gin.Context)
	VerifyEmail(*gin.Context)
	CreateTeam(*gin.Context)
	JoinTeam(*gin.Context)
	LeaveTeam(*gin.Context)
}

type templateDataModel struct {
	Cfg      *config.AppConfig
	Err      string
	Data     interface{}
	ReturnTo string
}

type frontendRouter struct {
	models.BaseRouter
	logger       *zap.Logger
	cfg          *config.AppConfig
	env          *environment.Env
	userService  services.UserService
	teamService  services.TeamService
	emailService services.EmailService
}

func NewRouter(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env, userService services.UserService, teamService services.TeamService, emailService services.EmailService) Router {
	return &frontendRouter{
		logger:       logger,
		cfg:          cfg,
		env:          env,
		userService:  userService,
		teamService:  teamService,
		emailService: emailService,
	}
}

func (r *frontendRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("", r.ProfilePage)
	routerGroup.GET("login", r.LoginPage)
	routerGroup.POST("login", r.Login)
	routerGroup.GET("logout", r.Logout)
	routerGroup.GET("register", r.RegisterPage)
	routerGroup.POST("register", r.Register)
	routerGroup.GET("forgotpwd", r.ForgotPasswordPage)
	routerGroup.POST("forgotpwd", r.ForgotPassword)
	routerGroup.GET("resetpwd", r.ResetPasswordPage)
	routerGroup.POST("resetpwd", r.ResetPassword)
	routerGroup.GET("verifyemail", r.VerifyEmail)
	routerGroup.POST("team/create", r.CreateTeam)
	routerGroup.POST("team/join", r.JoinTeam)
	routerGroup.POST("team/leave", r.LeaveTeam)
}
