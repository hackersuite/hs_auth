package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
)

func RegisterRoutes(logger *zap.Logger, routerGroup *gin.RouterGroup) {
	router := models.Router{Logger: logger}

	routerGroup.GET("/", router.Heartbeat)
}
