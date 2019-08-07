package models

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Router struct{}

type heartbeatResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *Router) Heartbeat(c *gin.Context) {
	message := fmt.Sprintf("request to %s received", c.Request.URL.String())

	c.JSON(http.StatusOK, heartbeatResponse{Status: "OK", Code: http.StatusOK, Message: message})
}
