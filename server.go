package main

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers"
)

func NewServer(mainRouter routers.MainRouter) *gin.Engine {
	server := gin.Default()

	mainRouter.RegisterRoutes(server.Group("/"))

	return server
}
