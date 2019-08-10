package services

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/repositories"
)

// UserService is the service for interactinos with the user collection
type UserService struct {
	userRepository repositories.UserRepository
}

// NewUserService creates a new UserService
func NewUserService(userRepository repositories.UserRepository) UserService {
	return UserService{
		userRepository: userRepository,
	}
}

// GetUserWithEmailAndPassword fetches a user with given email and password
func (s UserService) GetUserWithEmailAndPassword(ctx context.Context, email string, password string) (*entities.User, error) {
	res := s.userRepository.FindOne(ctx, bson.M{
		"email":    email,
		"password": password,
	})

	err := res.Err()
	if err != nil {
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
func (s UserService) GetUsers(ctx context.Context) ([]entities.User, error) {
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
