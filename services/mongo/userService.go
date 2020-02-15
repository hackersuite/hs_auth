package mongo

import (
	"context"
	"fmt"

	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/services"
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

type mongoUserService struct {
	logger         *zap.Logger
	env            *environment.Env
	cfg            *config.AppConfig
	userRepository *repositories.UserRepository
}

// NewMongoUserService creates a new UserService that uses MongoDB as the storage technology
func NewMongoUserService(logger *zap.Logger, env *environment.Env, cfg *config.AppConfig, userRepository *repositories.UserRepository) services.UserService {
	return &mongoUserService{
		logger:         logger,
		env:            env,
		cfg:            cfg,
		userRepository: userRepository,
	}
}

func (s *mongoUserService) CreateUser(ctx context.Context, name, email, password string) (*entities.User, error) {
	// check if email is not taken
	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserEmail): email,
	})

	err := res.Err()
	if err == nil {
		return nil, services.ErrEmailTaken
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
		AuthLevel: s.cfg.BaseAuthLevel,
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
		return nil, services.ErrInvalidID
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
		return nil, services.ErrInvalidID
	}

	fmt.Println(mongoID)

	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	})

	user, err := decodeUserResult(res)
	if errors.Cause(err) == mongo.ErrNoDocuments {
		return nil, services.ErrNotFound
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
	if errors.Cause(err) == mongo.ErrNoDocuments {
		return nil, services.ErrNotFound
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
		return nil, services.ErrNotFound
	}

	return user, nil
}

func (s *mongoUserService) GetUserWithJWT(ctx context.Context, jwt string) (*entities.User, error) {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return nil, services.ErrInvalidToken
	}

	return s.GetUserWithID(ctx, claims.Id)
}

func (s *mongoUserService) GetTeammatesForUserWithID(ctx context.Context, userID string) ([]entities.User, error) {
	user, err := s.GetUserWithID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.Team == primitive.NilObjectID {
		return nil, services.ErrUserNotInTeam
	}

	teamMembers, err := s.GetUsersWithTeam(ctx, user.Team.Hex())
	if err != nil {
		return nil, err
	}

	// removing the given user from the list of team members to ensure only the teammates are returned
	for i, member := range teamMembers {
		if member.ID == user.ID {
			teamMembers = append(teamMembers[:i], teamMembers[i+1:]...)
			break
		}
	}

	return teamMembers, nil
}

func (s *mongoUserService) GetTeammatesForUserWithJWT(ctx context.Context, jwt string) ([]entities.User, error) {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return nil, services.ErrInvalidToken
	}

	return s.GetTeammatesForUserWithID(ctx, claims.Id)
}

func (s *mongoUserService) UpdateUsersWithTeam(ctx context.Context, teamID string, params services.UserUpdateParams) error {
	mongoID, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return services.ErrInvalidID
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

func (s *mongoUserService) UpdateUsersWithAuthLevel(ctx context.Context, authLevel authlevels.AuthLevel, params services.UserUpdateParams) error {
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

func (s *mongoUserService) UpdateUserWithID(ctx context.Context, userID string, params services.UserUpdateParams) error {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return services.ErrInvalidID
	}

	res, err := s.userRepository.UpdateOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update user with ID")
	}

	if res.MatchedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}

func (s *mongoUserService) UpdateUserWithEmail(ctx context.Context, email string, params services.UserUpdateParams) error {
	res, err := s.userRepository.UpdateOne(ctx, bson.M{
		string(entities.UserEmail): email,
	}, bson.M{
		"$set": params,
	})
	if err != nil {
		return errors.Wrap(err, "could not update user with email")
	}

	if res.MatchedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}

func (s *mongoUserService) UpdateUserWithJWT(ctx context.Context, jwt string, params services.UserUpdateParams) error {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return services.ErrInvalidToken
	}

	return s.UpdateUserWithID(ctx, claims.Id, params)
}

func (s *mongoUserService) DeleteUserWithID(ctx context.Context, userID string) error {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return services.ErrInvalidID
	}

	res, err := s.userRepository.DeleteOne(ctx, bson.M{
		string(entities.UserID): mongoID,
	})
	if err != nil {
		return errors.Wrap(err, "could not delete user with ID")
	}

	if res.DeletedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}

func (s *mongoUserService) DeleteUserWithEmail(ctx context.Context, email string) error {
	res, err := s.userRepository.DeleteOne(ctx, bson.M{
		string(entities.UserEmail): email,
	})
	if err != nil {
		return errors.Wrap(err, "could not delete user with email")
	}

	if res.DeletedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}

func (s *mongoUserService) ResetPasswordForUserWithIDAndEmail(ctx context.Context, userID string, email string, newPwd string) error {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return services.ErrInvalidID
	}

	// hash password
	pwdHash, err := auth.GetHashForPassword(newPwd)
	if err != nil {
		return errors.Wrap(err, "could not hash password")
	}

	res, err := s.userRepository.UpdateOne(ctx, bson.M{
		string(entities.UserID):    mongoID,
		string(entities.UserEmail): email,
	}, bson.M{
		"$set": services.UserUpdateParams{
			entities.UserPassword: pwdHash,
		},
	})
	if err != nil {
		return errors.Wrap(err, "could not update user with ID and email")
	}

	if res.MatchedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}

func (s *mongoUserService) ResetPasswordForUserWithJWTAndEmail(ctx context.Context, jwt string, email string, newPwd string) error {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return services.ErrInvalidToken
	}

	return s.ResetPasswordForUserWithIDAndEmail(ctx, claims.Id, email, newPwd)
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
