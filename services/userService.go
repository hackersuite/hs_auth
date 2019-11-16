package services

import (
	"context"

	"go.uber.org/zap"

	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"

	"go.mongodb.org/mongo-driver/mongo"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/repositories"
)

// UserService is the service for interactions with a remote users repository
type UserService interface {
	GetUserWithID(context.Context, string) (*entities.User, error)
	GetUserWithEmail(context.Context, string) (*entities.User, error)
	GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error)
	GetUsers(context.Context) ([]entities.User, error)
	CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error)
	UpdateUserWithID(context.Context, string, map[string]interface{}) error
	UpdateUsersWithTeam(ctx context.Context, teamID string, fieldsToUpdate map[string]interface{}) error
	DeleteUserWithEmail(ctx context.Context, email string) error
}

type UserUpdateParams map[entities.UserField]interface{}

type UserServiceV2 interface {
	CreateUser(ctx context.Context, name, email, password string) (*entities.User, error)

	GetUsers(ctx context.Context) ([]entities.User, error)
	GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error)
	GetUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel) ([]entities.User, error)

	GetUserWithID(ctx context.Context, userID string) (*entities.User, error)
	GetUserWithEmail(ctx context.Context, email string) (*entities.User, error)
	GetUserWithEmailAndPwd(ctx context.Context, email, pwd string) (*entities.User, error)
	GetUserWithJWT(ctx context.Context, jwt string) (*entities.User, error)

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

type userService struct {
	logger         *zap.Logger
	userRepository *repositories.UserRepository
}

// NewUserService creates a new UserService
func NewUserService(logger *zap.Logger, userRepository *repositories.UserRepository) UserService {
	return &userService{
		logger:         logger,
		userRepository: userRepository,
	}
}

func (s *userService) GetUserWithID(ctx context.Context, id string) (*entities.User, error) {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, ErrInvalidID
	}

	res := s.userRepository.FindOne(ctx, bson.M{
		"_id": mongoID,
	})

	if err := res.Err(); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var user entities.User
	if err := res.Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserWithEmail fetches a user with given email
func (s *userService) GetUserWithEmail(ctx context.Context, email string) (*entities.User, error) {
	res := s.userRepository.FindOne(ctx, bson.M{
		"email": email,
	})

	err := res.Err()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var user entities.User

	err = res.Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUsers fetches all users
func (s *userService) GetUsers(ctx context.Context) ([]entities.User, error) {
	users := []entities.User{}

	cur, err := s.userRepository.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	// Decoding result
	for cur.Next(ctx) {
		var user entities.User
		err = cur.Decode(&user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// UpdateUserWithID updates a user with the given id with the values in fieldsToUpdate
// where the key must match the json name for the field to update in the user model
func (s *userService) UpdateUserWithID(ctx context.Context, id string, fieldsToUpdate map[string]interface{}) error {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return ErrInvalidID
	}

	if len(fieldsToUpdate) == 0 {
		return nil
	}

	_, err = s.userRepository.UpdateOne(ctx, bson.M{
		"_id": mongoID,
	}, bson.M{
		"$set": fieldsToUpdate,
	})

	return err
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error) {
	user := &entities.User{
		ID:        primitive.NewObjectID(),
		Name:      name,
		Email:     email,
		Password:  password,
		AuthLevel: authLevel,
	}

	_, err := s.userRepository.InsertOne(ctx, *user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) DeleteUserWithEmail(ctx context.Context, email string) error {
	_, err := s.userRepository.DeleteOne(ctx, bson.M{
		"email": email,
	})

	return err
}

func (s *userService) UpdateUsersWithTeam(ctx context.Context, teamID string, fieldsToUpdate map[string]interface{}) error {
	mongoID, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return ErrInvalidID
	}

	_, err = s.userRepository.UpdateMany(ctx, bson.M{
		"team": mongoID,
	}, bson.M{
		"$set": fieldsToUpdate,
	})

	return err
}

func (s *userService) GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error) {
	mongoID, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return nil, ErrInvalidID
	}

	cur, err := s.userRepository.Find(ctx, bson.M{
		"team": mongoID,
	})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var users []entities.User
	// Decoding result
	for cur.Next(ctx) {
		var user entities.User
		err = cur.Decode(&user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}
