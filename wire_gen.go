// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//+build !wireinject

package main

import (
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/routers"
	"github.com/unicsmcr/hs_auth/routers/api/v1"
	"github.com/unicsmcr/hs_auth/services"
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
	database, err := utils.NewDatabase(logger, env)
	if err != nil {
		return Server{}, err
	}
	userRepository, err := repositories.NewUserRepository(database)
	if err != nil {
		return Server{}, err
	}
	userService := services.NewUserService(logger, userRepository)
	emailService := services.NewEmailClient(logger, appConfig, env)
	apiv1Router := v1.NewAPIV1Router(logger, appConfig, userService, emailService, env)
	mainRouter := routers.NewMainRouter(logger, apiv1Router)
	server := NewServer(mainRouter, env)
	return server, nil
}
