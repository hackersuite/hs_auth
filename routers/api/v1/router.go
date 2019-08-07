package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

type APIV1Router struct {
	models.Router
	logger      *zap.Logger
	userService services.UserService
}

func NewAPIV1Router(logger *zap.Logger, userService services.UserService) APIV1Router {
	return APIV1Router{
		logger:      logger,
		userService: userService,
	}
}

func (r APIV1Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)
	routerGroup.GET("/users", r.GetUsers)
}
