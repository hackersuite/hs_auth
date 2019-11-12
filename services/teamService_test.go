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

func Test_CreateTeam__should_create_required_team(t *testing.T) {
	tRepo, tService := setupTeamTest(t)
	defer tRepo.Drop(context.Background())

	createdTeam, err := tService.CreateTeam(context.Background(), "test team 1", "2134abd12312312321312313")
	assert.NoError(t, err)

	teamOnDB, err := tService.GetTeamWithID(context.Background(), createdTeam.ID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, teamOnDB, createdTeam)
}

func Test_DeleteTeamWithID__should_delete_correct_team(t *testing.T) {
	tRepo, tService := setupTeamTest(t)
	defer tRepo.Drop(context.Background())

	testTeam, err := tService.CreateTeam(context.Background(), "test team 1", primitive.NewObjectID().Hex())
	assert.NoError(t, err)

	err = tService.DeleteTeamWithID(context.Background(), testTeam.ID.Hex())
	assert.NoError(t, err)

	_, err = tService.GetTeamWithID(context.Background(), testTeam.ID.Hex())
	assert.Error(t, err)

	assert.Equal(t, ErrNotFound, err)
}

func Test_UpdateTeamWithID__should_correctly_update_team(t *testing.T) {
	tRepo, tService := setupTeamTest(t)
	defer tRepo.Drop(context.Background())

	testTeam, err := tService.CreateTeam(context.Background(), "test team 1", primitive.NewObjectID().Hex())
	assert.NoError(t, err)

	err = tService.UpdateTeamWithID(context.Background(), testTeam.ID.Hex(), map[string]interface{}{
		"table_no": 5,
	})
	assert.NoError(t, err)

	testTeam.TableNo = 5

	actualTeam, err := tService.GetTeamWithID(context.Background(), testTeam.ID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, testTeam, actualTeam)
}

func Test_GetTeamWithName(t *testing.T) {
	tests := []struct {
		name     string
		teamName string
		prep     func(repositories.TeamRepository)
		wantTeam *entities.Team
		wantErr  error
	}{
		{
			name:     "should return error if team with given name doesn't exist",
			teamName: "non-existant team",
			wantErr:  ErrNotFound,
		},
		{
			name:     "should return correct team",
			teamName: "test team 1",
			prep: func(tRepo repositories.TeamRepository) {
				_, err := tRepo.InsertOne(context.Background(), entities.Team{
					Name: "test team 1",
				})
				assert.NoError(t, err)
			},
			wantTeam: &entities.Team{
				Name: "test team 1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tRepo, tService := setupTeamTest(t)
			defer tRepo.Drop(context.Background())
			if tt.prep != nil {
				tt.prep(tRepo)
			}

			team, err := tService.GetTeamWithName(context.Background(), tt.teamName)

			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.wantTeam, team)
		})
	}
}

func Test_GetTeamWithID__should_return_error(t *testing.T) {
	tests := []errTeamTestCase{
		{
			name:    "when given id is invalid",
			wantErr: ErrInvalidID,
		},
		{
			name:    "when team with given id doesn't exist",
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

func Test_DeleteTeamWithID__should_return_error(t *testing.T) {
	tests := []errTeamTestCase{
		{
			name:    "when given id is invalid",
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tRepo, tService := setupTeamTest(t)
			defer tRepo.Drop(context.Background())
			if tt.prep != nil {
				tt.prep(t, tRepo)
			}

			err := tService.DeleteTeamWithID(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func Test_UpdateTeamWithID__should_return_error(t *testing.T) {
	tests := []errTeamTestCase{
		{
			name:    "when given id is invalid",
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tRepo, tService := setupTeamTest(t)
			defer tRepo.Drop(context.Background())
			if tt.prep != nil {
				tt.prep(t, tRepo)
			}

			err := tService.UpdateTeamWithID(context.Background(), tt.id, nil)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}
