package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

// APIV1Router is the router for v1 of the API
type APIV1Router struct {
	models.Router
	logger      *zap.Logger
	userService services.UserService
	env         *environment.Env
}

// NewAPIV1Router creates a APIV1Router
func NewAPIV1Router(logger *zap.Logger, userService services.UserService, env *environment.Env) APIV1Router {
	return APIV1Router{
		logger:      logger,
		userService: userService,
		env:         env,
	}
}

// RegisterRoutes registers all of the API's (v1) routes to the given router group
func (r APIV1Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	usersGroup := routerGroup.Group("/users")

	usersGroup.GET("/", r.getUsers)
	usersGroup.POST("/login", r.login)
}
