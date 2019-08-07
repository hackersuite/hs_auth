package services

import (
	"context"

	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/repositories"
)

type UserService struct {
	userRepository repositories.UserRepository
}

func NewUserService(userRepository repositories.UserRepository) UserService {
	return UserService{
		userRepository: userRepository,
	}
}

func (s UserService) GetUsers(ctx context.Context) ([]entities.User, error) {
	users := []entities.User{}

	cur, err := s.userRepository.Find(ctx, entities.User{})
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
