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

	teamRepository, err := repositories.NewTeamRepository(db)
	assert.NoError(t, err)

	teamService := NewTeamService(zap.NewNop(), teamRepository)

	err = teamRepository.Drop(context.Background())
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

func Test_GetTeamWithID__should_return_correct_team(t *testing.T) {
	tRepo, tService := setupTeamTest(t)
	defer tRepo.Drop(context.Background())

	testID, err := primitive.ObjectIDFromHex("2134abd12312312321312313")
	assert.NoError(t, err)

	testTeam := entities.Team{
		ID:   testID,
		Name: "test team 1",
	}

	_, err = tRepo.InsertOne(context.Background(), testTeam)
	assert.NoError(t, err)

	team, err := tService.GetTeamWithID(context.Background(), testID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, testTeam, *team)
}

func Test_GetTeamWithID__should_return_error(t *testing.T) {
	tests := []errTeamTestCase{
		{
			name:    "when given id is invalid",
			wantErr: ErrInvalidID,
		},
		{
			name:    "when user with given id doesn't exist",
			id:      "2134abd12312312321312313",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tRepo, tService := setupTeamTest(t)
			defer tRepo.Drop(context.Background())
			if tt.prep != nil {
				tt.prep(t, tRepo)
			}

			_, err := tService.GetTeamWithID(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}
