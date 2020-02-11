package services

import (
	"context"

	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/unicsmcr/hs_auth/entities"
)

type UserUpdateParams map[entities.UserField]interface{}

// UserService is the service for interactions with a remote users repository
type UserService interface {
	CreateUser(ctx context.Context, name, email, password string) (*entities.User, error)

	GetUsers(ctx context.Context) ([]entities.User, error)
	GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error)
	GetUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel) ([]entities.User, error)

	GetUserWithID(ctx context.Context, userID string) (*entities.User, error)
	GetUserWithEmail(ctx context.Context, email string) (*entities.User, error)
	GetUserWithEmailAndPwd(ctx context.Context, email, pwd string) (*entities.User, error)
	GetUserWithJWT(ctx context.Context, jwt string) (*entities.User, error)

	GetTeammatesForUserWithID(ctx context.Context, userID string) ([]entities.User, error)
	GetTeammatesForUserWithJWT(ctx context.Context, jwt string) ([]entities.User, error)

	UpdateUsersWithTeam(ctx context.Context, teamID string, params UserUpdateParams) error
	UpdateUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel, params UserUpdateParams) error

	UpdateUserWithID(ctx context.Context, userID string, params UserUpdateParams) error
	UpdateUserWithEmail(ctx context.Context, email string, params UserUpdateParams) error
	UpdateUserWithJWT(ctx context.Context, jwt string, params UserUpdateParams) error

	DeleteUserWithID(ctx context.Context, userID string) error
	DeleteUserWithEmail(ctx context.Context, email string) error

	ResetPasswordForUserWithIDAndEmail(ctx context.Context, userID string, email string, newPwd string) error
	ResetPasswordForUserWithJWTAndEmail(ctx context.Context, jwt string, email string, newPwd string) error
}
