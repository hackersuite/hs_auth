package config

import (
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/environment"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.uber.org/config"
)

var (
	// Paths to the config files from the the project's root folder
	baseConfigFile = "./config/base.yaml"
	devConfigFile  = "./config/development.yaml"
	prodConfigFile = "./config/production.yaml"
	roleConfigFile = "./config/role/role.yaml"
)

// EmailConfig stores the configuration to be used by the email service
type EmailConfig struct {
	HelpEmailAddr              string `yaml:"help_email_addr"`
	NoreplyEmailAddr           string `yaml:"noreply_email_addr"`
	NoreplyEmailName           string `yaml:"noreply_email_name"`
	EmailVerificationEmailSubj string `yaml:"email_verification_email_subj"`
	PasswordResetEmailSubj     string `yaml:"password_reset_email_subj"`
	TokenLifetime              int64  `yaml:"token_lifetime"`
}

// AuthConfig stores the configuration to be used by the auth system V2
type AuthConfig struct {
	UserTokenLifetime         int64         `yaml:"user_token_lifetime""`
	DefaultRole               role.UserRole `yaml:"default_role"`
	EmailVerificationRequired bool          `yaml:"email_verification_required"`
	// The role that gets assigned to the user after they verify their email
	DefaultEmailVerifiedRole role.UserRole `yaml:"default_email_verified_role"`
}

// AppConfig is a struct to store non-private configuration for the project
type AppConfig struct {
	Name               string               `yaml:"name"`
	DomainName         string               `yaml:"domain_name"` // this is the domain under which all cookies will be stored
	UseSecureCookies   bool                 `yaml:"use_secure_cookies"`
	BaseAuthLevel      authlevels.AuthLevel `yaml:"base_auth_level"`
	AuthTokenLifetime  int64                `yaml:"auth_token_lifetime"`
	AppURL             string               `yaml:"app_url"`
	Email              EmailConfig          `yaml:"email"`
	UserRole           role.UserRoleConfig  `yaml:"role"`
	DataPolicyURL      string               `yaml:"data_policy_url"`
	SoftMaxTeamMembers uint                 `yaml:"soft_max_team_members"`
	Auth               AuthConfig           `yaml:"auth"`
}

// NewAppConfig loads the project config from the config files based on the environment
func NewAppConfig(env *environment.Env) (*AppConfig, error) {
	var configProvider *config.YAML
	var err error
	configFiles := []config.YAMLOption{config.File(roleConfigFile), config.File(baseConfigFile)}
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
