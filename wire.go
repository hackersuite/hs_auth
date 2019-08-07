//+build wireinject

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/google/wire"
	"github.com/unicsmcr/hs_auth/routers"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"
	"github.com/unicsmcr/hs_auth/utils"
)

func InitializeServer() (*gin.Engine, error) {
	wire.Build(NewServer, routers.NewMainRouter, v1.NewAPIV1Router, utils.NewLogger)
	return &gin.Engine{}, nil
}
