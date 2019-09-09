package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/testutils"

	"github.com/unicsmcr/hs_auth/environment"
)

func Test_NewAppConfig__should_return_correct_config_when_ENVIRONMENT_is_prod(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{environment.Environment: "prod"})
	defer restoreVars()

	env := environment.NewEnv(zap.NewNop())

	config, err := NewAppConfig(env)
	assert.NoError(t, err)

	assert.Equal(t, "Hacker Suite - Auth", config.Name)
}

func Test_NewAppConfig__should_return_correct_config_when_ENVIRONMENT_is_dev(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{environment.Environment: "dev"})
	defer restoreVars()

	env := environment.NewEnv(zap.NewNop())

	config, err := NewAppConfig(env)
	assert.NoError(t, err)

	assert.Equal(t, "Hacker Suite - Auth (dev)", config.Name)
}
