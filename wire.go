//+build wireinject

package main

import (
	"github.com/google/wire"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/routers"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"
	"github.com/unicsmcr/hs_auth/routers/frontend"
	"github.com/unicsmcr/hs_auth/services/mongo"
	"github.com/unicsmcr/hs_auth/services/sendgrid"
	"github.com/unicsmcr/hs_auth/utils"
)

func InitializeServer() (Server, error) {
	wire.Build(
		NewServer,
		routers.NewMainRouter,
		frontend.NewRouter,
		v1.NewAPIV1Router,
		mongo.NewMongoTeamService,
		mongo.NewMongoUserService,
		sendgrid.NewSendgridEmailService,
		repositories.NewUserRepository,
		repositories.NewTeamRepository,
		utils.NewDatabase,
		utils.NewSendgridClient,
		environment.NewEnv,
		utils.NewLogger,
		config.NewAppConfig,
	)
	return Server{}, nil
}
