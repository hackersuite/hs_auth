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
	configFiles := []config.YAMLOption{config.File("base.yaml")}
	if env.Get(environment.Environment) == "prod" {
		configFiles = append(configFiles, config.File("production.yaml"))
	} else if env.Get(environment.Environment) == "dev" {
		configFiles = append(configFiles, config.File("development.yaml"))
	}
	configProvider, err = config.NewYAML(configFiles...)
	if err != nil {
		return nil, err
	}

	var cfg AppConfig

	err = configProvider.Get("").Populate(&cfg)
	return &cfg, nil
}
