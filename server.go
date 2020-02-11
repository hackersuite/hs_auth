package main

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers"
)

type Server struct {
	*gin.Engine
	Port string
}

func NewServer(mainRouter routers.MainRouter, env *environment.Env) Server {
	server := Server{
		Engine: gin.Default(),
		Port:   env.Get(environment.Port),
	}

	server.Static("static", "static")
	server.LoadHTMLGlob("templates/*/*.gohtml")

	mainRouter.RegisterRoutes(server.Group("/"))

	return server
}
