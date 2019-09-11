package services

import (
	"context"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/utils/auth"

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
	GetUserWithEmailAndPassword(context.Context, string, string) (*entities.User, error)
	GetUsers(context.Context) ([]entities.User, error)
	CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error)
	UpdateUserWithID(context.Context, string, map[string]interface{}) error
}

type userService struct {
	logger         *zap.Logger
	userRepository repositories.UserRepository
}

// NewUserService creates a new UserService
func NewUserService(logger *zap.Logger, userRepository repositories.UserRepository) UserService {
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

// GetUserWithEmailAndPassword fetches a user with given email and password
func (s *userService) GetUserWithEmailAndPassword(ctx context.Context, email string, password string) (*entities.User, error) {
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

	err = auth.CompareHashAndPassword(user.Password, password)
	if err != nil {
		return nil, ErrNotFound
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

	_, err = s.userRepository.UpdateOne(ctx, bson.M{
		"_id": mongoID,
	}, bson.M{
		"$set": fieldsToUpdate,
	})

	return err
}

// CreateUser creates a new user with a hashed password
func (s *userService) CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error) {
	hashedPassword, err := auth.GetHashForPassword(password)
	if err != nil {
		return nil, err
	}

	user := &entities.User{
		Name:      name,
		Email:     email,
		Password:  hashedPassword,
		AuthLevel: authLevel,
	}

	_, err = s.userRepository.InsertOne(ctx, *user)
	if err != nil {
		return nil, err
	}

	return user, nil
}
