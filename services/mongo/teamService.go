package mongo

import (
	"context"

	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type mongoTeamService struct {
	logger         *zap.Logger
	env            *environment.Env
	teamRepository *repositories.TeamRepository
	userService    services.UserServiceV2
}

// NewMongoTeamService creates a new TeamServiceV2 that uses MongoDB as the storage technology
func NewMongoTeamService(logger *zap.Logger, env *environment.Env, teamRepository *repositories.TeamRepository, userService services.UserServiceV2) services.TeamServiceV2 {
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
