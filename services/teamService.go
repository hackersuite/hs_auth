package services

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/repositories"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/entities"
)

// TeamService is the service for interactions with a remote teams repository
type TeamService interface {
	GetTeams(context.Context) ([]entities.Team, error)
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
