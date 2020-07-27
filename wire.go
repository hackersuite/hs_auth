//+build wireinject

package main

import (
	"github.com/google/wire"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/routers"
	v1 "github.com/unicsmcr/hs_auth/routers/api/v1"
	v2 "github.com/unicsmcr/hs_auth/routers/api/v2"
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
		v2.NewAPIV2Router,
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
		utils.NewTimeProvider,
		authV2.NewAuthorizer,
	)
	return Server{}, nil
}
