package mongo

import (
	"context"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/utils"
	"strings"

	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
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

func (s *mongoUserService) CreateUser(ctx context.Context, name, email, password string, role role.UserRole) (*entities.User, error) {
	formattedEmail := strings.ToLower(email)

	// check if email is not taken
	res := s.userRepository.FindOne(ctx, bson.M{
		string(entities.UserEmail): formattedEmail,
	})

	err := res.Err()
	if err == nil {
		return nil, services.ErrEmailTaken
	} else if err != mongo.ErrNoDocuments {
		return nil, errors.Wrap(err, "could not query for user with email")
	}

	// hash password
	pwdHash, err := utils.GetHashForPassword(password)
	if err != nil {
		return nil, errors.Wrap(err, "could not hash password")
	}

	user := &entities.User{
		ID:        primitive.NewObjectID(),
		Name:      name,
		Email:     formattedEmail,
		Password:  pwdHash,
		AuthLevel: s.cfg.BaseAuthLevel,
		Role:      role,
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

func (s *mongoUserService) GetUserWithID(ctx context.Context, userID string) (*entities.User, error) {
	mongoID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, services.ErrInvalidID
	}

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
		string(entities.UserEmail): strings.ToLower(email),
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

	err = utils.CompareHashAndPassword(user.Password, pwd)
	if err != nil {
		return nil, services.ErrNotFound
	}

	return user, nil
}

func (s *mongoUserService) GetTeamMembersForUserWithID(ctx context.Context, userID string) ([]entities.User, error) {
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

	return teamMembers, nil
}

func (s *mongoUserService) GetTeammatesForUserWithID(ctx context.Context, userID string) ([]entities.User, error) {
	teamMembers, err := s.GetTeamMembersForUserWithID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// removing the given user from the list of team members to ensure only the teammates are returned
	for i, member := range teamMembers {
		if member.ID.Hex() == userID {
			teamMembers = append(teamMembers[:i], teamMembers[i+1:]...)
			break
		}
	}

	return teamMembers, nil
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
	pwdHash, err := utils.GetHashForPassword(newPwd)
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
