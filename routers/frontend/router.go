package frontend

import (
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/routers/common"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.uber.org/zap"
	"net/http"
)

const authCookieName = "Authorization"

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
	VerifyEmailResend(*gin.Context)
	EmailUnverifiedPage(*gin.Context)
	CreateTeam(*gin.Context)
	JoinTeam(*gin.Context)
	LeaveTeam(*gin.Context)
	UpdateUser(*gin.Context)
	ProfilePage(*gin.Context)
}

type frontendRouter struct {
	models.BaseRouter
	logger         *zap.Logger
	cfg            *config.AppConfig
	env            *environment.Env
	userService    services.UserService
	teamService    services.TeamService
	emailService   services.EmailService
	emailServiceV2 services.EmailServiceV2
	authorizer     authV2.Authorizer
	timeProvider   utils.TimeProvider
}

func (r *frontendRouter) GetResourcePath() string {
	return common.FrontendResourcePath
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
	r.renderPage(ctx, loginPage, http.StatusUnauthorized, nil, "You do not have permissions to access this operation")
	ctx.Abort()
	return
}

func NewRouter(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env, userService services.UserService,
	teamService services.TeamService, emailService services.EmailService, authorizer authV2.Authorizer,
	timeProvider utils.TimeProvider, emailServiceV2 services.EmailServiceV2) Router {
	return &frontendRouter{
		logger:         logger,
		cfg:            cfg,
		env:            env,
		userService:    userService,
		teamService:    teamService,
		emailService:   emailService,
		authorizer:     authorizer,
		timeProvider:   timeProvider,
		emailServiceV2: emailServiceV2,
	}
}

func (r *frontendRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	isAtLeastApplicant := auth.AuthLevelVerifierFactory(authlevels.Applicant, r.GetAuthToken, []byte(r.env.Get(environment.JWTSecret)), r.HandleUnauthorized)
	isAtLeastOrganiser := auth.AuthLevelVerifierFactory(authlevels.Organiser, r.GetAuthToken, []byte(r.env.Get(environment.JWTSecret)), r.HandleUnauthorized)

	emailVerificationRouter := emailVerificationRouter{
		frontendRouter: *r,
	}

	routerGroup.GET("", r.authorizer.WithAuthMiddleware(r, r.ProfilePage))
	routerGroup.GET("login", r.LoginPage)
	routerGroup.POST("login", r.Login)
	routerGroup.GET("logout", r.authorizer.WithAuthMiddleware(r, r.Logout))
	routerGroup.GET("register", r.RegisterPage)
	routerGroup.POST("register", r.Register)
	routerGroup.GET("forgotpwd", r.ForgotPasswordPage)
	routerGroup.POST("forgotpwd", r.ForgotPassword)
	routerGroup.GET("resetpwd", r.ResetPasswordPage)
	routerGroup.POST("resetpwd", r.authorizer.WithAuthMiddleware(r, r.ResetPassword))
	routerGroup.GET("verifyemail", r.authorizer.WithAuthMiddleware(&emailVerificationRouter, r.VerifyEmail))
	routerGroup.GET("verifyemail/resend", r.authorizer.WithAuthMiddleware(r, r.VerifyEmailResend))
	routerGroup.GET("emailunverified", r.authorizer.WithAuthMiddleware(r, r.EmailUnverifiedPage))
	routerGroup.POST("team/create", isAtLeastApplicant, r.CreateTeam)
	routerGroup.POST("team/join", isAtLeastApplicant, r.JoinTeam)
	routerGroup.POST("team/leave", isAtLeastApplicant, r.LeaveTeam)
	routerGroup.POST("user/update/:id", isAtLeastOrganiser, r.UpdateUser)
}

func (r *frontendRouter) renderPage(ctx *gin.Context, page frontendPage, statusCode int, pageData interface{}, alertMessage string) {
	authorizedComponentURIs, err := r.authorizer.GetAuthorizedResources(ctx, r.GetAuthToken(ctx), page.componentURIs)
	if err != nil {
		switch errors.Cause(err) {
		case authCommon.ErrInvalidToken:
			r.logger.Debug("invalid auth token")
			ctx.HTML(http.StatusUnauthorized, "login.gohtml", pageDataModel{
				Cfg:   *r.cfg,
				Alert: "You are not authorized to view this page",
			})
		default:
			r.logger.Error("could not get authorized resources", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", pageDataModel{
				Cfg:   *r.cfg,
				Alert: "Something went wrong",
			})
		}
		return
	}

	authorizedComponents := page.getComponentsWithURIs(authorizedComponentURIs)

	var componentsToRender = make(map[string]interface{})
	for _, component := range authorizedComponents {
		componentData, err := component.dataProvider(ctx, r)
		if err != nil {
			r.logger.Error("could not fetch data for component", zap.String("component", component.name), zap.Error(err))
		} else {
			componentsToRender[component.name] = componentData
		}
	}

	ctx.HTML(statusCode, page.templateName, pageDataModel{
		Cfg:            *r.cfg,
		Alert:          alertMessage,
		Components:     componentsToRender,
		CustomPageData: pageData,
	})
}

// RouterResource implementation for email verification.
// Modifies frontendRouter's auth token extraction function to deal with the way
// the token is provided to the VerifyEmail operation
type emailVerificationRouter struct {
	frontendRouter
}

func (r *emailVerificationRouter) GetAuthToken(ctx *gin.Context) string {
	return ctx.Query("token")
}
