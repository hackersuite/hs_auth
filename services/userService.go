package services

import (
	"context"

	"github.com/unicsmcr/hs_auth/entities"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ValidateUserUpdateParams validates provided params are correct and safe to
// be used for updating the data on the database. Returns nil if all parameters are valid,
// ErrInvalidUserUpdateParams otherwise.
func ValidateUserUpdateParams(params UserUpdateParams) error {
	for field, value := range params {
		switch field {
		case entities.UserID, entities.UserTeam:
			if _, ok := value.(primitive.ObjectID); !ok {
				return ErrInvalidUserUpdateParams
			}
			break
		case entities.UserName, entities.UserEmail, entities.UserPassword:
			if _, ok := value.(string); !ok {
				return ErrInvalidUserUpdateParams
			}
			break
		case entities.UserEmailVerified:
			if _, ok := value.(bool); !ok {
				return ErrInvalidUserUpdateParams
			}
			break
		case entities.UserAuthLevel:
			if _, ok := value.(authlevels.AuthLevel); !ok {
				return ErrInvalidUserUpdateParams
			}
			break
		}
	}

	return nil
}

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
