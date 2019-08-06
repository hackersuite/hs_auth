package models

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Router struct {
	Logger *zap.Logger
}

type heartbeatResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *Router) Heartbeat(c *gin.Context) {
	r.Logger.Info("request received", zap.String("host", c.Request.RemoteAddr))

	message := fmt.Sprintf("request to %s received", c.Request.URL.String())

	c.JSON(http.StatusOK, heartbeatResponse{Status: "OK", Code: http.StatusOK, Message: message})
}
