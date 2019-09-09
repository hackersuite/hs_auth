package environment

import (
	"testing"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/testutils"

	"github.com/stretchr/testify/assert"
)

func Test_NewEnv__should_return_correct_env(t *testing.T) {
	vars := map[string]string{
		Environment:   "testenv",
		Port:          "testport",
		MongoHost:     "testmongohost",
		MongoDatabase: "testmongodatabase",
		MongoUser:     "testmongouser",
		MongoPassword: "testmongopassword",
		JWTSecret:     "testsecret",
	}

	restoreVars := testutils.SetEnvVars(vars)
	defer restoreVars()

	expectedEnv := Env{
		vars: vars,
	}

	assert.Equal(t, expectedEnv, *NewEnv(zap.NewNop()))
}

func Test_Get__should_return_correct_value(t *testing.T) {
	env := &Env{
		vars: map[string]string{
			Environment:   "testenv",
			Port:          "testport",
			MongoHost:     "testmongohost",
			MongoDatabase: "testmongodatabase",
			MongoUser:     "testmongouser",
			MongoPassword: "testmongopassword",
			JWTSecret:     "testsecret",
		},
	}

	tests := []struct {
		name string
		want string
		args string
	}{
		{
			name: Environment,
			want: env.vars[Environment],
			args: Environment,
		},
		{
			name: Port,
			want: env.vars[Port],
			args: Port,
		},
		{
			name: MongoHost,
			want: env.vars[MongoHost],
			args: MongoHost,
		},
		{
			name: MongoDatabase,
			want: env.vars[MongoDatabase],
			args: MongoDatabase,
		},
		{
			name: MongoUser,
			want: env.vars[MongoUser],
			args: MongoUser,
		},
		{
			name: MongoPassword,
			want: env.vars[MongoPassword],
			args: MongoPassword,
		},
		{
			name: JWTSecret,
			want: env.vars[JWTSecret],
			args: JWTSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, env.Get(tt.args))
		})
	}
}

func Test_valueOfEnvVar__should_return_correct_value(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{"testkey": "testvalue"})
	defer restoreVars()

	value := valueOfEnvVar(zap.NewNop(), "testkey")
	assert.Equal(t, "testvalue", value)
}

func Test_valueOfEnvVar__should_return_empty_string_when_var_not_set(t *testing.T) {
	restoreVars := testutils.UnsetVars("testkey")
	defer restoreVars()

	value := valueOfEnvVar(zap.NewNop(), "testkey")
	assert.Equal(t, "", value)
}
