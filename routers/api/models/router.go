package models

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Router is the basic model for a requests routers
type Router struct{}

type heartbeatResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Heartbeat sends an HTTP_OK response to the user
func (r *Router) Heartbeat(ctx *gin.Context) {
	message := fmt.Sprintf("request to %s received", ctx.Request.URL.String())

	ctx.JSON(http.StatusOK, heartbeatResponse{Status: "OK", Code: http.StatusOK, Message: message})
}
