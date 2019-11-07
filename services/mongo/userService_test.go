package mongo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/services"
)

func Test_ErrInvalidID_should_be_returned_when_provided_id_is_invalid(t *testing.T) {
	uService := &mongoUserService{}

	tests := []struct {
		name         string
		testFunction func(id string) error
	}{
		{
			name: "GetUsersWithTeam",
			testFunction: func(id string) error {
				_, err := uService.GetUsersWithTeam(context.Background(), id)
				return err
			},
		},
		{
			name: "GetUserWithID",
			testFunction: func(id string) error {
				_, err := uService.GetUserWithID(context.Background(), id)
				return err
			},
		},
		{
			name: "UpdateUsersWithTeam",
			testFunction: func(id string) error {
				return uService.UpdateUsersWithTeam(context.Background(), id, UserUpdateParams{})
			},
		},
		{
			name: "UpdateUserWithID",
			testFunction: func(id string) error {
				return uService.UpdateUserWithID(context.Background(), id, UserUpdateParams{})
			},
		},
		{
			name: "DeleteUserWithID",
			testFunction: func(id string) error {
				return uService.DeleteUserWithID(context.Background(), id)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidID, tt.testFunction("invalid ID"))
		})
	}
}
