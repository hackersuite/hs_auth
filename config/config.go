package config

import (
	"github.com/unicsmcr/hs_auth/environment"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"

	"go.uber.org/config"
)

var (
	// Paths to the config files from the the project's root folder
	baseConfigFile = "./config/base.yaml"
	devConfigFile  = "./config/development.yaml"
	prodConfigFile = "./config/production.yaml"
)

// EmailConfig stores the configuration to be used by the email service
type EmailConfig struct {
	HelpEmailAddr             string `yaml:"help_email_addr"`
	NoreplyEmailAddr          string `yaml:"noreply_email_addr"`
	NoreplyEmailName          string `yaml:"noreply_email_name"`
	EmailVerficationEmailSubj string `yaml:"email_verification_email_subj"`
	PasswordResetEmailSubj    string `yaml:"password_reset_email_subj"`
}

// AppConfig is a struct to store non-private configuration for the project
type AppConfig struct {
	Name              string               `yaml:"name"`
	BaseAuthLevel     authlevels.AuthLevel `yaml:"base_auth_level"`
	AuthTokenLifetime int64                `yaml:"auth_token_lifetime"`
	AppURL            string               `yaml:"app_url"`
	Email             EmailConfig          `yaml:"email"`
}

// NewAppConfig loads the project config from the config files based on the environment
func NewAppConfig(env *environment.Env) (*AppConfig, error) {
	var configProvider *config.YAML
	var err error
	configFiles := []config.YAMLOption{config.File(baseConfigFile)}
	if env.Get(environment.Environment) == "prod" {
		configFiles = append(configFiles, config.File(prodConfigFile))
	} else if env.Get(environment.Environment) == "dev" {
		configFiles = append(configFiles, config.File(devConfigFile))
	}
	configProvider, err = config.NewYAML(configFiles...)
	if err != nil {
		return nil, err
	}

	var cfg AppConfig

	err = configProvider.Get("").Populate(&cfg)
	return &cfg, nil
}
