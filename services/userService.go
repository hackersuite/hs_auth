package services

import (
	"context"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/config/role"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"strconv"

	"github.com/unicsmcr/hs_auth/entities"
)

func BuildUserUpdateParams(cfg *config.AppConfig, stringParams map[entities.UserField]string) (builtParams UserUpdateParams, err error) {
	builtParams = UserUpdateParams{}
	for field, value := range stringParams {
		switch field {
		case entities.UserID, entities.UserTeam:
			builtParams[field], err = primitive.ObjectIDFromHex(value)
			if err != nil {
				return UserUpdateParams{}, ErrInvalidUserUpdateParams
			}
			break
		case entities.UserName, entities.UserEmail, entities.UserPassword:
			builtParams[field] = value
			break
		case entities.UserAuthLevel:
			builtParams[field], err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return UserUpdateParams{}, ErrInvalidUserUpdateParams
			}
			break
		case entities.UserRole:
			if err := cfg.UserRole.ValidateRole(role.UserRole(value)); err != nil {
				return UserUpdateParams{}, errors.Wrap(ErrInvalidUserUpdateParams, err.Error())
			}
			builtParams[field] = value
		}
	}
	return builtParams, nil
}

type UserUpdateParams map[entities.UserField]interface{}

// UserService is the service for interactions with a remote users repository
type UserService interface {
	CreateUser(ctx context.Context, name, email, password string, role role.UserRole) (*entities.User, error)

	GetUsers(ctx context.Context) ([]entities.User, error)
	GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error)

	GetUserWithID(ctx context.Context, userID string) (*entities.User, error)
	GetUserWithEmail(ctx context.Context, email string) (*entities.User, error)
	GetUserWithEmailAndPwd(ctx context.Context, email, pwd string) (*entities.User, error)

	GetTeamMembersForUserWithID(ctx context.Context, userID string) ([]entities.User, error)

	GetTeammatesForUserWithID(ctx context.Context, userID string) ([]entities.User, error)

	UpdateUsersWithTeam(ctx context.Context, teamID string, params UserUpdateParams) error

	UpdateUserWithID(ctx context.Context, userID string, params UserUpdateParams) error
	UpdateUserWithEmail(ctx context.Context, email string, params UserUpdateParams) error

	DeleteUserWithID(ctx context.Context, userID string) error
	DeleteUserWithEmail(ctx context.Context, email string) error

	ResetPasswordForUserWithIDAndEmail(ctx context.Context, userID string, email string, newPwd string) error
}
