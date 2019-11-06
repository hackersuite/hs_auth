package services

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/entities"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
)

type UserUpdateParams map[entities.UserField]interface{}

type UserServiceV2 interface {
	CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error)

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
}

type mongoUserService struct {
	logger         *zap.Logger
	env            *environment.Env
	userRepository repositories.UserRepository
}

func NewUserServiceV2(logger *zap.Logger, env *environment.Env, userRepository repositories.UserRepository) UserServiceV2 {
	return &mongoUserService{
		logger:         logger,
		env:            env,
		userRepository: userRepository,
	}
}

func (s *mongoUserService) CreateUser(ctx context.Context, name, email, password string, authLevel authlevels.AuthLevel) (*entities.User, error) {
	// check if email is not taken
	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserEmail): email,
	})

	err := res.Err()
	if err == nil {
		return nil, ErrEmailTaken
	} else if err != mongo.ErrNoDocuments {
		return nil, errors.Wrap(err, "could not query for user with email")
	}

	// hash password
	pwdHash, err := auth.GetHashForPassword(password)
	if err != nil {
		return nil, errors.Wrap(err, "could not hash password")
	}

	user := &entities.User{
		ID:        primitive.NewObjectID(),
		Name:      name,
		Email:     email,
		Password:  pwdHash,
		AuthLevel: authLevel,
	}

	_, err = s.userRepository.InsertOne(ctx, *user)
	if err != nil {
		return nil, errors.Wrap(err, "could not create new user")
	}

	return user, nil
}

func (s *mongoUserService) GetUsers(ctx context.Context) ([]entities.User, error) {
	cur, err := s.userRepository.Find(ctx, bson.M{})
	if err != nil {
		return nil, errors.Wrap(err, "could not query for users")
	}
	defer cur.Close(ctx)

	users, err := decodeUsersResult(ctx, cur)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode result")
	}

	return users, nil
}

func (s *mongoUserService) GetUsersWithTeam(ctx context.Context, teamID string) ([]entities.User, error) {
	mongoID, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return nil, ErrInvalidID
	}

	cur, err := s.userRepository.Find(ctx, bson.M{
		string(entities.UserTeam): mongoID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not query for users with team")
	}
	defer cur.Close(ctx)

	users, err := decodeUsersResult(ctx, cur)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode result")
	}

	return users, nil
}

func (s *mongoUserService) GetUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel) ([]entities.User, error) {
	cur, err := s.userRepository.Find(ctx, bson.M{
		string(entities.UserAuthLevel): authLevel,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not query for users with auth level")
	}
	defer cur.Close(ctx)

	users, err := decodeUsersResult(ctx, cur)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode result")
	}

	return users, nil
}

func (s *mongoUserService) GetUserWithID(ctx context.Context, userID string) (*entities.User, error) {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, ErrInvalidID
	}

	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	})

	user, err := decodeUserResult(res)
	if errors.Cause(err) != mongo.ErrNoDocuments {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "could not query for user with ID")
	}

	return user, nil
}

func (s *mongoUserService) GetUserWithEmail(ctx context.Context, email string) (*entities.User, error) {
	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserEmail): email,
	})

	user, err := decodeUserResult(res)
	if errors.Cause(err) != mongo.ErrNoDocuments {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "could not query for user with email")
	}

	return user, nil
}

func (s *mongoUserService) GetUserWithEmailAndPwd(ctx context.Context, email, pwd string) (*entities.User, error) {
	user, err := s.GetUserWithEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	err = auth.CompareHashAndPassword(user.Password, pwd)
	if err != nil {
		return nil, ErrNotFound
	}

	return user, nil
}

func (s *mongoUserService) GetUserWithJWT(ctx context.Context, jwt string) (*entities.User, error) {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return nil, ErrInvalidToken
	}

	return s.GetUserWithID(ctx, claims.Id)
}

func (s *mongoUserService) UpdateUsersWithTeam(ctx context.Context, teamID string, params UserUpdateParams) error {
	mongoID, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return ErrInvalidID
	}

	_, err = s.userRepository.UpdateMany(ctx, bson.M{
		string(entities.UserTeam): mongoID,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update users with team")
	}

	return nil
}

func (s *mongoUserService) UpdateUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel, params UserUpdateParams) error {
	_, err := s.userRepository.UpdateMany(ctx, bson.M{
		string(entities.UserAuthLevel): authLevel,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update users with auth level")
	}

	return nil
}

func (s *mongoUserService) UpdateUserWithID(ctx context.Context, userID string, params UserUpdateParams) error {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return ErrInvalidID
	}

	_, err = s.userRepository.UpdateOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update user with ID")
	}

	return nil
}

func (s *mongoUserService) UpdateUserWithEmail(ctx context.Context, email string, params UserUpdateParams) error {
	_, err := s.userRepository.UpdateOne(ctx, bson.M{
		string(entities.UserEmail): email,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update user with email")
	}

	return nil
}

func (s *mongoUserService) UpdateUserWithJWT(ctx context.Context, jwt string, params UserUpdateParams) error {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return ErrInvalidToken
	}

	return s.UpdateUserWithID(ctx, claims.Id, params)
}

func (s *mongoUserService) DeleteUserWithID(ctx context.Context, userID string) error {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return ErrInvalidID
	}

	_, err = s.userRepository.DeleteOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	})
	if err != nil {
		return errors.Wrap(err, "could not delete user with ID")
	}

	return nil
}

func (s *mongoUserService) DeleteUserWithEmail(ctx context.Context, email string) error {
	_, err := s.userRepository.DeleteOne(ctx, bson.M{
		string(entities.UserEmail): email,
	})
	if err != nil {
		return errors.Wrap(err, "could not delete user with email")
	}

	return nil
}

func decodeUserResult(res *mongo.SingleResult) (*entities.User, error) {
	err := res.Err()
	if err != nil {
		return nil, errors.Wrap(err, "query returned error")
	}

	var user entities.User
	err = res.Decode(&user)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode user")
	}

	return &user, nil
}

func decodeUsersResult(ctx context.Context, cur *mongo.Cursor) ([]entities.User, error) {
	var users []entities.User
	for cur.Next(ctx) {
		var user entities.User
		err := cur.Decode(&user)
		if err != nil {
			return nil, errors.Wrap(err, "could not decode user")
		}
		users = append(users, user)
	}

	return users, nil
}
