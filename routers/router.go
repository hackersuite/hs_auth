package routers

import (
	"github.com/unicsmcr/hs_auth/routers/api/models"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(logger *zap.Logger, routerGroup *gin.RouterGroup) {
	router := models.Router{Logger: logger}

	routerGroup.GET("/", router.Heartbeat)

	apiV1 := routerGroup.Group("/api/v1")
	v1.RegisterRoutes(logger, apiV1)
}
