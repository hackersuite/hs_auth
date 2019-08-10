package config

import (
	"github.com/unicsmcr/hs_auth/environment"

	"go.uber.org/config"
)

type AppConfig struct{}

func NewAppConfig(env *environment.Env) (*AppConfig, error) {
	var configProvider *config.YAML
	var err error
	if env.GetEnvironment() == "prod" {
		configProvider, err = config.NewYAML(config.File("base.yaml"), config.File("production.yaml"))
	} else {
		configProvider, err = config.NewYAML(config.File("base.yaml"), config.File("development.yaml"))
	}
	if err != nil {
		return nil, err
	}

	var cfg AppConfig

	err = configProvider.Get("").Populate(&cfg)
	return &cfg, nil
}
