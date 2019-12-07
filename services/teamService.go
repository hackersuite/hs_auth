package services

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/repositories"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/entities"
)

// TeamService is the service for interactions with a remote teams repository
type TeamService interface {
	GetTeams(context.Context) ([]entities.Team, error)
	GetTeamWithID(ctx context.Context, id string) (*entities.Team, error)
	GetTeamWithName(ctx context.Context, name string) (*entities.Team, error)
	CreateTeam(ctx context.Context, name, creatorID string) (*entities.Team, error)
	DeleteTeamWithID(ctx context.Context, id string) error
}

type TeamServiceV2 interface {
	CreateTeam(ctx context.Context, name, creatorID string) (*entities.Team, error)
	CreateTeamForUserWithID(ctx context.Context, name, userID string) (*entities.Team, error)
	CreateTeamForUserWithJWT(ctx context.Context, name, jwt string) (*entities.Team, error)

	GetTeams(context.Context) ([]entities.Team, error)

	GetTeamWithID(ctx context.Context, id string) (*entities.Team, error)
	GetTeamWithName(ctx context.Context, name string) (*entities.Team, error)
	GetTeamForUserWithID(ctx context.Context, userID string) (*entities.Team, error)
	GetTeamForUserWithEmail(ctx context.Context, email string) (*entities.Team, error)
	GetTeamForUserWithJWT(ctx context.Context, jwt string) (*entities.Team, error)

	DeleteTeamWithID(ctx context.Context, id string) error

	AddUserWithIDToTeamWithID(ctx context.Context, userID string, teamID string) error
	AddUserWithJWTToTeamWithID(ctx context.Context, jwt string, teamID string) error

	RemoveUserWithIDFromTheirTeam(ctx context.Context, userID string) error
	RemoveUserWithJWTFromTheirTeam(ctx context.Context, jwt string) error
}

type teamService struct {
	logger         *zap.Logger
	teamRepository repositories.TeamRepository
}

// NewTeamService creates a new TeamService
func NewTeamService(logger *zap.Logger, teamRepository repositories.TeamRepository) TeamService {
	return &teamService{
		logger:         logger,
		teamRepository: teamRepository,
	}
}

func (s *teamService) GetTeams(ctx context.Context) ([]entities.Team, error) {
	teams := []entities.Team{}

	cur, err := s.teamRepository.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	// Decoding result
	for cur.Next(ctx) {
		var team entities.Team
		err = cur.Decode(&team)
		if err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}

	return teams, nil
}

func (s *teamService) GetTeamWithID(ctx context.Context, id string) (*entities.Team, error) {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, ErrInvalidID
	}

	res := s.teamRepository.FindOne(ctx, bson.M{
		"_id": mongoID,
	})

	if err := res.Err(); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var team entities.Team
	if err := res.Decode(&team); err != nil {
		return nil, err
	}

	return &team, nil
}

func (s *teamService) GetTeamWithName(ctx context.Context, name string) (*entities.Team, error) {
	res := s.teamRepository.FindOne(ctx, bson.M{
		"name": name,
	})

	if err := res.Err(); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var team entities.Team
	if err := res.Decode(&team); err != nil {
		return nil, err
	}

	return &team, nil
}

func (s *teamService) CreateTeam(ctx context.Context, name, creatorID string) (*entities.Team, error) {
	creatorMongoID, err := primitive.ObjectIDFromHex(creatorID)
	if err != nil {
		return nil, ErrInvalidID
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

func (s *teamService) DeleteTeamWithID(ctx context.Context, id string) error {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return ErrInvalidID
	}

	_, err = s.teamRepository.DeleteOne(ctx, bson.M{
		"_id": mongoID,
	})
	return err
}
