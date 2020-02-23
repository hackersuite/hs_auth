package services

import (
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
)

func Test_ValidateUserUpdateParams__should_return_err_when_params_are_invalid(t *testing.T) {
	tests := []struct {
		name   string
		params UserUpdateParams
	}{
		{
			name: "id",
			params: UserUpdateParams{
				entities.UserID: 3,
			},
		},
		{
			name: "name",
			params: UserUpdateParams{
				entities.UserName: 3,
			},
		},
		{
			name: "email",
			params: UserUpdateParams{
				entities.UserEmail: 3,
			},
		},
		{
			name: "password",
			params: UserUpdateParams{
				entities.UserPassword: 3,
			},
		},
		{
			name: "email verified",
			params: UserUpdateParams{
				entities.UserEmailVerified: 3,
			},
		},
		{
			name: "auth level",
			params: UserUpdateParams{
				entities.UserAuthLevel: "3",
			},
		},
		{
			name: "team",
			params: UserUpdateParams{
				entities.UserTeam: 3,
			},
		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, ErrInvalidUserUpdateParams, ValidateUserUpdateParams(tt.params))
		})
	}
}

func Test_ValidateUserUpdateParams__should_return_nil_when_params_are_valid(t *testing.T) {
	assert.Nil(t, ValidateUserUpdateParams(UserUpdateParams{
		entities.UserID: primitive.NewObjectID(),
		entities.UserTeam: primitive.NewObjectID(),
		entities.UserName: "Bob the Tester",
		entities.UserPassword: "password123",
		entities.UserEmail: "bob@tester.com",
		entities.UserEmailVerified: true,
		entities.UserAuthLevel: common.Organizer,
	}))
}