package mongo

import (
	"context"

	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type mongoTeamService struct {
	logger         *zap.Logger
	env            *environment.Env
	teamRepository *repositories.TeamRepository
	userService    services.UserService
}

// NewMongoTeamService creates a new TeamService that uses MongoDB as the storage technology
func NewMongoTeamService(logger *zap.Logger, env *environment.Env, teamRepository *repositories.TeamRepository, userService services.UserService) services.TeamService {
	return &mongoTeamService{
		logger:         logger,
		env:            env,
		teamRepository: teamRepository,
		userService:    userService,
	}
}

func (s *mongoTeamService) CreateTeam(ctx context.Context, name, creatorID string) (*entities.Team, error) {
	creatorMongoID, err := primitive.ObjectIDFromHex(creatorID)
	if err != nil {
		return nil, services.ErrInvalidID
	}

	// check if name is not taken
	res := s.teamRepository.FindOne(ctx, bson.M{
		string(entities.TeamName): name,
	})

	err = res.Err()
	if err == nil {
		return nil, services.ErrNameTaken
	} else if err != mongo.ErrNoDocuments {
		return nil, errors.Wrap(err, "could not query for team with name")
	}

	team := &entities.Team{
		ID:      primitive.NewObjectID(),
		Name:    name,
		Creator: creatorMongoID,
	}

	_, err = s.teamRepository.InsertOne(ctx, *team)
	if err != nil {
		return nil, err
	}

	return team, nil
}

func (s *mongoTeamService) CreateTeamForUserWithID(ctx context.Context, name, userID string) (*entities.Team, error) {
	user, err := s.userService.GetUserWithID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.Team != primitive.NilObjectID {
		return nil, services.ErrUserInTeam
	}

	team, err := s.CreateTeam(ctx, name, userID)
	if err != nil {
		return nil, err
	}

	err = s.userService.UpdateUserWithID(ctx, userID, services.UserUpdateParams{
		entities.UserTeam: team.ID,
	})
	if err != nil {
		err := s.DeleteTeamWithID(ctx, team.ID.Hex())
		if err != nil {
			s.logger.Error("could not delete team after adding user to new team failed", zap.Error(err))
		}
		return nil, errors.Wrap(err, "could not add user to new team")
	}

	return team, nil
}

func (s *mongoTeamService) CreateTeamForUserWithJWT(ctx context.Context, name, jwt string) (*entities.Team, error) {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return nil, services.ErrInvalidToken
	}

	return s.CreateTeamForUserWithID(ctx, name, claims.Id)
}

func (s *mongoTeamService) GetTeams(ctx context.Context) ([]entities.Team, error) {
	cur, err := s.teamRepository.Find(ctx, bson.M{})
	if err != nil {
		return nil, errors.Wrap(err, "could not query for teams")
	}
	defer cur.Close(ctx)

	teams, err := decodeTeamsResult(ctx, cur)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode result")
	}

	return teams, nil
}

func (s *mongoTeamService) GetTeamWithID(ctx context.Context, id string) (*entities.Team, error) {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, services.ErrInvalidID
	}

	res := s.teamRepository.FindOne(ctx, bson.M{
		string(entities.TeamID): mongoID,
	})

	team, err := decodeTeamResult(res)
	if errors.Cause(err) == mongo.ErrNoDocuments {
		return nil, services.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "could not query for team with ID")
	}

	return team, nil
}

func (s *mongoTeamService) GetTeamWithName(ctx context.Context, name string) (*entities.Team, error) {
	res := s.teamRepository.FindOne(ctx, bson.M{
		string(entities.TeamName): name,
	})

	team, err := decodeTeamResult(res)
	if errors.Cause(err) == mongo.ErrNoDocuments {
		return nil, services.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "could not query for team with ID")
	}

	return team, nil
}

func (s *mongoTeamService) GetTeamForUserWithID(ctx context.Context, userID string) (*entities.Team, error) {
	user, err := s.userService.GetUserWithID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return s.GetTeamWithID(ctx, user.Team.Hex())
}

func (s *mongoTeamService) GetTeamForUserWithEmail(ctx context.Context, email string) (*entities.Team, error) {
	user, err := s.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return s.GetTeamWithID(ctx, user.Team.Hex())
}

func (s *mongoTeamService) GetTeamForUserWithJWT(ctx context.Context, jwt string) (*entities.Team, error) {
	user, err := s.userService.GetUserWithJWT(ctx, jwt)
	if err != nil {
		return nil, err
	}

	return s.GetTeamWithID(ctx, user.Team.Hex())
}

func (s *mongoTeamService) DeleteTeamWithID(ctx context.Context, id string) error {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return services.ErrInvalidID
	}

	res, err := s.teamRepository.DeleteOne(ctx, bson.M{
		string(entities.TeamID): mongoID,
	})
	if err != nil {
		return err
	} else if res.DeletedCount == 0 {
		return services.ErrNotFound
	}

	return err
}

func (s *mongoTeamService) AddUserWithIDToTeamWithID(ctx context.Context, userID string, teamID string) error {
	team, err := s.GetTeamWithID(ctx, teamID)
	if err != nil {
		return err
	}

	// TODO: missing error handling
	user, err := s.userService.GetUserWithID(ctx, userID)
	if user.Team != primitive.NilObjectID {
		return services.ErrUserInTeam
	}

	return s.userService.UpdateUserWithID(ctx, userID, services.UserUpdateParams{
		entities.UserTeam: team.ID,
	})
}

func (s *mongoTeamService) AddUserWithJWTToTeamWithID(ctx context.Context, jwt string, teamID string) error {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return services.ErrInvalidToken
	}

	return s.AddUserWithIDToTeamWithID(ctx, claims.Id, teamID)
}

func (s *mongoTeamService) RemoveUserWithIDFromTheirTeam(ctx context.Context, userID string) error {
	user, err := s.userService.GetUserWithID(ctx, userID)
	if err != nil {
		return err
	}

	if user.Team == primitive.NilObjectID {
		return services.ErrUserNotInTeam
	}

	team, err := s.GetTeamWithID(ctx, user.Team.Hex())
	if err != nil {
		return err
	}

	err = s.userService.UpdateUserWithID(ctx, userID, services.UserUpdateParams{
		entities.UserTeam: primitive.NilObjectID,
	})
	if err != nil {
		return err
	}

	if team.Creator != user.ID {
		return nil
	}

	// Removed team's creator from the team, need to assign new creator
	teamMembers, err := s.userService.GetUsersWithTeam(ctx, team.ID.Hex())
	if err != nil {
		return err
	}

	if len(teamMembers) == 0 { // team is empty, should be deleted
		return s.DeleteTeamWithID(ctx, team.ID.Hex())
	}

	_, err = s.teamRepository.UpdateOne(ctx, bson.M{
		string(entities.TeamID): team.ID,
	}, bson.M{
		"$set": map[entities.TeamField]interface{}{
			entities.TeamCreator: teamMembers[0].ID,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *mongoTeamService) RemoveUserWithJWTFromTheirTeam(ctx context.Context, jwt string) error {
	claims := auth.GetJWTClaims(jwt, []byte(s.env.Get(environment.JWTSecret)))
	if claims == nil {
		return services.ErrInvalidToken
	}

	return s.RemoveUserWithIDFromTheirTeam(ctx, claims.Id)
}

func decodeTeamResult(res *mongo.SingleResult) (*entities.Team, error) {
	err := res.Err()
	if err != nil {
		return nil, errors.Wrap(err, "query returned error")
	}

	var team entities.Team
	err = res.Decode(&team)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode team")
	}

	return &team, nil
}

func decodeTeamsResult(ctx context.Context, cur *mongo.Cursor) ([]entities.Team, error) {
	var teams []entities.Team
	for cur.Next(ctx) {
		var team entities.Team
		err := cur.Decode(&team)
		if err != nil {
			return nil, errors.Wrap(err, "could not decode team")
		}
		teams = append(teams, team)
	}

	return teams, nil
}
