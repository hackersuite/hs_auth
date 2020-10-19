package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	v2 "github.com/unicsmcr/hs_auth/routers/api/v2"
	"github.com/unicsmcr/hs_auth/routers/frontend"
	"go.uber.org/zap"
)

// MainRouter is router to connect all routers used by the app
type MainRouter interface {
	models.Router
}

type mainRouter struct {
	models.BaseRouter
	logger         *zap.Logger
	apiV2          v2.APIV2Router
	frontendRouter frontend.Router
}

// NewMainRouter creates a new MainRouter
func NewMainRouter(logger *zap.Logger, apiV2Router v2.APIV2Router, frontendRouter frontend.Router) MainRouter {
	return &mainRouter{
		logger:         logger,
		apiV2:          apiV2Router,
		frontendRouter: frontendRouter,
	}
}

// RegisterRoutes registers all of the app's routes
func (r *mainRouter) RegisterRoutes(routerGroup *gin.RouterGroup) {
	frontendGroup := routerGroup.Group("/")
	r.frontendRouter.RegisterRoutes(frontendGroup)

	apiV2Group := routerGroup.Group("/api/v2")
	r.apiV2.RegisterRoutes(apiV2Group)
}
