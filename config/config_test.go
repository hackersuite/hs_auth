package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.uber.org/config"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/testutils"

	"github.com/unicsmcr/hs_auth/environment"
)

func Test_NewAppConfig__should_return_correct_config_when_ENVIRONMENT_is_prod(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{environment.Environment: "prod"})
	defer restoreVars()

	baseConfigFile = "base.yaml"
	prodConfigFile = "production.yaml"

	env := environment.NewEnv(zap.NewNop())

	actualConfig, err := NewAppConfig(env)
	assert.NoError(t, err)

	configProvider, err := config.NewYAML(config.File("base.yaml"), config.File("production.yaml"))
	assert.NoError(t, err)
	var expectedConfig AppConfig
	err = configProvider.Get("").Populate(&expectedConfig)
	assert.NoError(t, err)

	assert.Equal(t, expectedConfig.Name, actualConfig.Name)
	assert.Equal(t, expectedConfig.BaseAuthLevel, actualConfig.BaseAuthLevel)
}

func Test_NewAppConfig__should_return_correct_config_when_ENVIRONMENT_is_dev(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{environment.Environment: "dev"})
	defer restoreVars()

	baseConfigFile = "base.yaml"
	devConfigFile = "development.yaml"

	env := environment.NewEnv(zap.NewNop())

	actualConfig, err := NewAppConfig(env)
	assert.NoError(t, err)

	configProvider, err := config.NewYAML(config.File("base.yaml"), config.File("development.yaml"))
	assert.NoError(t, err)
	var expectedConfig AppConfig
	err = configProvider.Get("").Populate(&expectedConfig)
	assert.NoError(t, err)

	assert.Equal(t, expectedConfig.Name, actualConfig.Name)
	assert.Equal(t, expectedConfig.BaseAuthLevel, actualConfig.BaseAuthLevel)
}
