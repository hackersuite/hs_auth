// +build integration

package services

import (
	"context"
	"testing"

	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
)

type errTeamTestCase struct {
	id      string
	name    string
	creator string
	prep    func(t *testing.T, repo repositories.TeamRepository)
	wantErr error
}

func setupTeamTest(t *testing.T) (repositories.TeamRepository, TeamService) {
	db := testutils.ConnectToIntegrationTestDB(t)

	teamRepository := repositories.NewTeamRepository(db)
	teamService := NewTeamService(zap.NewNop(), teamRepository)

	err := teamRepository.Drop(context.Background())
	assert.NoError(t, err)

	return teamRepository, teamService
}

func Test_GetTeams__should_return_correct_teams(t *testing.T) {
	tRepo, tService := setupTeamTest(t)
	defer tRepo.Drop(context.Background())

	testTeams := []entities.Team{
		{
			ID:   primitive.NewObjectID(),
			Name: "Team 1",
		},
		{
			ID:   primitive.NewObjectID(),
			Name: "Team 2",
		},
	}

	_, err := tRepo.InsertMany(context.Background(), []interface{}{testTeams[0], testTeams[1]})
	assert.NoError(t, err)

	teams, err := tService.GetTeams(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, testTeams, teams)
}
