package config

import (
	"github.com/unicsmcr/hs_auth/environment"

	"go.uber.org/config"
)

// AppConfig is a struct to store non-private configuration for the project
type AppConfig struct{}

// NewAppConfig loads the project config from the config files based on the environment
func NewAppConfig(env *environment.Env) (*AppConfig, error) {
	var configProvider *config.YAML
	var err error
	if env.Get(environment.Environment) == "prod" {
		configProvider, err = config.NewYAML(config.File("base.yaml"), config.File("production.yaml"))
	} else if env.Get(environment.Environment) == "dev" {
		configProvider, err = config.NewYAML(config.File("base.yaml"), config.File("development.yaml"))
	} else {
		configProvider, err = config.NewYAML(config.File("base.yaml"))
	}
	if err != nil {
		return nil, err
	}

	var cfg AppConfig

	err = configProvider.Get("").Populate(&cfg)
	return &cfg, nil
}
