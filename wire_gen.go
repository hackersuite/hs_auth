// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package main

import (
	"github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/routers"
	v2_3 "github.com/unicsmcr/hs_auth/routers/api/v2"
	"github.com/unicsmcr/hs_auth/routers/frontend"
	"github.com/unicsmcr/hs_auth/services/mongo"
	v2_2 "github.com/unicsmcr/hs_auth/services/sendgrid/v2"
	"github.com/unicsmcr/hs_auth/utils"
)

// Injectors from wire.go:

func InitializeServer() (Server, error) {
	logger, err := utils.NewLogger()
	if err != nil {
		return Server{}, err
	}
	env := environment.NewEnv(logger)
	appConfig, err := config.NewAppConfig(env)
	if err != nil {
		return Server{}, err
	}
	timeProvider := utils.NewTimeProvider()
	database, err := utils.NewDatabase(logger, env)
	if err != nil {
		return Server{}, err
	}
	tokenRepository, err := repositories.NewTokenRepository(database)
	if err != nil {
		return Server{}, err
	}
	tokenService := mongo.NewMongoTokenService(logger, env, tokenRepository)
	userRepository, err := repositories.NewUserRepository(database)
	if err != nil {
		return Server{}, err
	}
	userService := mongo.NewMongoUserService(logger, env, appConfig, userRepository)
	authorizer := v2.NewAuthorizer(timeProvider, appConfig, env, logger, tokenService, userService)
	teamRepository, err := repositories.NewTeamRepository(database)
	if err != nil {
		return Server{}, err
	}
	teamService := mongo.NewMongoTeamService(logger, env, teamRepository, userService)
	client := utils.NewSendgridClient(env)
	emailServiceV2, err := v2_2.NewSendgridEmailServiceV2(appConfig, env, client, userService, authorizer, timeProvider)
	if err != nil {
		return Server{}, err
	}
	apiv2Router := v2_3.NewAPIV2Router(logger, appConfig, authorizer, userService, teamService, tokenService, emailServiceV2, timeProvider)
	router := frontend.NewRouter(logger, appConfig, env, userService, teamService, authorizer, timeProvider, emailServiceV2)
	mainRouter := routers.NewMainRouter(logger, apiv2Router, router)
	server := NewServer(mainRouter, env)
	return server, nil
}
