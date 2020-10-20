package environment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
)

func Test_NewEnv__should_return_correct_env(t *testing.T) {
	vars := map[string]string{
		Environment:    "testenv",
		Port:           "testport",
		MongoHost:      "testmongohost",
		MongoDatabase:  "testmongodatabase",
		MongoUser:      "testmongouser",
		MongoPassword:  "testmongopassword",
		JWTSecret:      "testsecret",
		SendgridAPIKey: "testsendgridkey",
		SMTPUsername:   "testsmtpusername",
		SMTPPassword:   "testsmtppassword",
		SMTPHost:       "testsmtphost",
		SMTPPort:       "testsmtpport",
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
			Environment:    "testenv",
			Port:           "testport",
			MongoHost:      "testmongohost",
			MongoDatabase:  "testmongodatabase",
			MongoUser:      "testmongouser",
			MongoPassword:  "testmongopassword",
			JWTSecret:      "testsecret",
			SendgridAPIKey: "testkey",
			SMTPUsername:   "testsmtpusername",
			SMTPPassword:   "testsmtppassword",
			SMTPHost:       "testsmtphost",
			SMTPPort:       "testsmtpport",
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
		{
			name: SendgridAPIKey,
			want: env.vars[SendgridAPIKey],
			args: SendgridAPIKey,
		},
		{
			name: SMTPUsername,
			want: env.vars[SMTPUsername],
			args: SMTPUsername,
		},
		{
			name: SMTPPassword,
			want: env.vars[SMTPPassword],
			args: SMTPPassword,
		},
		{
			name: SMTPHost,
			want: env.vars[SMTPHost],
			args: SMTPHost,
		},
		{
			name: SMTPPort,
			want: env.vars[SMTPPort],
			args: SMTPPort,
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

func Test_Get__should_return_not_set_when_env_var_is_not_set(t *testing.T) {
	vars := map[string]string{}

	restoreVars := testutils.SetEnvVars(vars)
	defer restoreVars()

	env := NewEnv(zap.NewNop())

	assert.Equal(t, DefaultEnvVarValue, env.Get("not set var"))
}
