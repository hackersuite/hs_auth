package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
)

type APIV1Router struct {
	models.Router
	logger *zap.Logger
}

func NewAPIV1Router(logger *zap.Logger) APIV1Router {
	return APIV1Router{
		logger: logger,
	}
}

func (r APIV1Router) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)
}
