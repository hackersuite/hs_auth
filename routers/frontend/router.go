package frontend

import (
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.uber.org/zap"
)

const resourcePath = "hs:hs_auth:frontend"
const authCookieName = "Authorization"

func jwtProvider(ctx *gin.Context) string {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		return ""
	}
	return jwt
}

func invalidJWTHandler(ctx *gin.Context) {
	ctx.Redirect(http.StatusSeeOther, "/login")
	ctx.Abort()
	return
}

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
	UpdateUser(*gin.Context)
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
	authorizer   authV2.Authorizer
	timeProvider utils.TimeProvider
}

func (r *frontendRouter) GetResourcePath() string {
	return resourcePath
}

func (r *frontendRouter) GetAuthToken(ctx *gin.Context) string {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		r.logger.Debug("could not retrieve auth token", zap.Error(err))
		return ""
	}

	return jwt
}

func (r *frontendRouter) HandleUnauthorized(ctx *gin.Context) {
	invalidJWTHandler(ctx)
}

func NewRouter(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env, userService services.UserService, teamService services.TeamService, emailService services.EmailService, authorizer authV2.Authorizer, timeProvider utils.TimeProvider) Router {
	return &frontendRouter{
		logger:       logger,
		cfg:          cfg,
		env:          env,
		userService:  userService,
		teamService:  teamService,
		emailService: emailService,
		authorizer:   authorizer,
		timeProvider: timeProvider,
	}
}

func (r *frontendRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	isAtLeastUnverified := auth.AuthLevelVerifierFactory(authlevels.Unverified, jwtProvider, []byte(r.env.Get(environment.JWTSecret)), invalidJWTHandler)
	isAtLeastApplicant := auth.AuthLevelVerifierFactory(authlevels.Applicant, jwtProvider, []byte(r.env.Get(environment.JWTSecret)), invalidJWTHandler)
	isAtLeastOrganiser := auth.AuthLevelVerifierFactory(authlevels.Organiser, jwtProvider, []byte(r.env.Get(environment.JWTSecret)), invalidJWTHandler)

	routerGroup.GET("", isAtLeastApplicant, r.ProfilePage)
	routerGroup.GET("login", r.LoginPage)
	routerGroup.POST("login", r.Login)
	routerGroup.GET("logout", isAtLeastUnverified, r.Logout)
	routerGroup.GET("register", r.RegisterPage)
	routerGroup.POST("register", r.Register)
	routerGroup.GET("forgotpwd", r.ForgotPasswordPage)
	routerGroup.POST("forgotpwd", r.ForgotPassword)
	routerGroup.GET("resetpwd", r.ResetPasswordPage)
	routerGroup.POST("resetpwd", r.ResetPassword)
	routerGroup.GET("verifyemail", r.VerifyEmail)
	routerGroup.GET("verifyemail/resend", isAtLeastUnverified, r.VerifyEmailResend)
	routerGroup.GET("emailunverified", isAtLeastUnverified, r.EmailUnverifiedPage)
	routerGroup.POST("team/create", isAtLeastApplicant, r.CreateTeam)
	routerGroup.POST("team/join", isAtLeastApplicant, r.JoinTeam)
	routerGroup.POST("team/leave", isAtLeastApplicant, r.LeaveTeam)
	routerGroup.POST("user/update/:id", isAtLeastOrganiser, r.UpdateUser)
}
