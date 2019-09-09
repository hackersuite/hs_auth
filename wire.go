//+build wireinject

package main

import (
	"github.com/google/wire"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/routers"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
)

func InitializeServer() (Server, error) {
	wire.Build(
		NewServer,
		routers.NewMainRouter,
		v1.NewAPIV1Router,
		services.NewUserService,
		repositories.NewUserRepository,
		utils.NewDatabase,
		environment.NewEnv,
		utils.NewLogger,
		// config.NewAppConfig,
	)
	return Server{}, nil
}
