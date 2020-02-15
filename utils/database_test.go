// +build integration

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
)

func Test_NewDatabase__should_return_connection_to_hs_auth_database(t *testing.T) {
	restore := testutils.SetEnvVars(map[string]string{
		environment.MongoUser:     "hs_auth",
		environment.MongoPassword: "password123",
		environment.MongoHost:     "127.0.0.1:8003",
		environment.MongoDatabase: "hs_auth",
	})
	defer restore()

	env := environment.NewEnv(zap.NewNop())

	db, err := NewDatabase(zap.NewNop(), env)
	assert.NoError(t, err)

	assert.Equal(t, "hs_auth", db.Name())
}

func Test_NewDatabase__should_return_error_when_user_credentials_are_incorrect(t *testing.T) {
	restore := testutils.SetEnvVars(map[string]string{
		environment.MongoUser:     "hs_auth",
		environment.MongoPassword: "password12",
		environment.MongoHost:     "127.0.0.1:8003",
		environment.MongoDatabase: "hs_auth",
	})
	defer restore()

	env := environment.NewEnv(zap.NewNop())

	_, err := NewDatabase(zap.NewNop(), env)
	assert.Error(t, err)
}

func Test_NewDatabase__should_return_error_some_connection_var_is_undefined(t *testing.T) {
	restore := testutils.SetEnvVars(map[string]string{
		environment.MongoUser:     "",
		environment.MongoPassword: "password123",
		environment.MongoHost:     "127.0.0.1:8003",
		environment.MongoDatabase: "hs_auth",
	})
	defer restore()

	env := environment.NewEnv(zap.NewNop())

	_, err := NewDatabase(zap.NewNop(), env)
	assert.Error(t, err)
}
