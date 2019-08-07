package routers

import (
	"github.com/unicsmcr/hs_auth/routers/api/models"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"
)

type MainRouter struct {
	models.Router
	logger *zap.Logger
	apiV1  v1.APIV1Router
}

func NewMainRouter(logger *zap.Logger, apiV1Router v1.APIV1Router) MainRouter {
	return MainRouter{
		logger: logger,
		apiV1:  apiV1Router,
	}
}

func (r MainRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	routerGroup.GET("/", r.Heartbeat)

	apiV1Group := routerGroup.Group("/api/v1")
	r.apiV1.RegisterRoutes(apiV1Group)
}
