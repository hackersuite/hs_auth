package utils

import (
	"testing"

	"github.com/unicsmcr/hs_auth/testutils"

	"github.com/stretchr/testify/assert"

	"github.com/unicsmcr/hs_auth/environment"
)

func Test_NewLogger__should_not_throw_error_when_ENVIRONMENT_not_set(t *testing.T) {
	restoreVars := testutils.UnsetVars(environment.Environment)
	defer restoreVars()

	logger, err := NewLogger()
	assert.NoError(t, err)
	assert.NotNil(t, logger)
}

func Test_NewLogger__should_not_throw_error_when_ENVIRONMENT_is_set_to_prod(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{environment.Environment: "prod"})
	defer restoreVars()

	logger, err := NewLogger()
	assert.NoError(t, err)
	assert.NotNil(t, logger)
}
