package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/unicsmcr/hs_auth/environment"
)

func Test_NewLogger__should_not_throw_error_when_ENVIRONMENT_not_set(t *testing.T) {
	initialValue, exists := os.LookupEnv(environment.Environment)
	err := os.Unsetenv(environment.Environment)
	assert.NoError(t, err)
	if exists {
		defer os.Setenv(environment.Environment, initialValue)
	}

	logger, err := NewLogger()
	assert.NoError(t, err)
	assert.NotNil(t, logger)
}

func Test_NewLogger__should_not_throw_error_when_ENVIRONMENT_is_set_to_prod(t *testing.T) {
	initialValue, exists := os.LookupEnv(environment.Environment)
	err := os.Setenv(environment.Environment, "prod")
	assert.NoError(t, err)

	if exists {
		defer os.Setenv(environment.Environment, initialValue)
	}

	logger, err := NewLogger()
	assert.NoError(t, err)
	assert.NotNil(t, logger)
}
