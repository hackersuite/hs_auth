// +build integration

package mongo

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var (
	testTeam = entities.Team{
		Name:    "Team of Bobs",
		Creator: primitive.NewObjectID(),
	}
)

type teamTestSetup struct {
	tService     *mongoTeamService
	tRepo        *repositories.TeamRepository
	mockUService *mock_services.MockUserServiceV2
	cleanup      func()
}

func setupTeamTest(t *testing.T) *teamTestSetup {
	db := testutils.ConnectToIntegrationTestDB(t)

	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserServiceV2(ctrl)

	tRepo, err := repositories.NewTeamRepository(db)
	if err != nil {
		panic(err)
	}

	resetEnv := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: testJWTSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	resetEnv()

	tService := &mongoTeamService{
		logger:         zap.NewNop(),
		env:            env,
		teamRepository: tRepo,
		userService:    mockUService,
	}

	return &teamTestSetup{
		tService:     tService,
		tRepo:        tRepo,
		mockUService: mockUService,
		cleanup: func() {
			tRepo.Drop(context.Background())
		},
	}
}

func Test_NewMongoTeamService__should_return_non_nil_object(t *testing.T) {
	assert.NotNil(t, NewMongoTeamService(nil, nil, nil, nil))
}

func Test_Team_ErrInvalidID_should_be_returned_when_provided_id_is_invalid(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	tests := []struct {
		name         string
		testFunction func(id string) error
	}{
		{
			name: "CreateTeam",
			testFunction: func(id string) error {
				_, err := setup.tService.CreateTeam(context.Background(), "", id)
				return err
			},
		},
		{
			name: "GetTeamWithID",
			testFunction: func(id string) error {
				_, err := setup.tService.GetTeamWithID(context.Background(), id)
				return err
			},
		},
		{
			name: "DeleteTeamWithID",
			testFunction: func(id string) error {
				err := setup.tService.DeleteTeamWithID(context.Background(), id)
				return err
			},
		},
		{
			name: "AddUserWithIDToTeamWithID",
			testFunction: func(id string) error {
				err := setup.tService.AddUserWithIDToTeamWithID(context.Background(), id, "")
				return err
			},
		},
		{
			name: "RemoveUserWithIDFromTheirTeam",
			testFunction: func(id string) error {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), id).Return(nil, services.ErrInvalidID).Times(1)
				err := setup.tService.RemoveUserWithIDFromTheirTeam(context.Background(), id)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidID, tt.testFunction("invalid ID"))
		})
	}
}

func Test_Team_ErrInvalidToken_should_be_returned_when_provided_JWT_is_invalid(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	tests := []struct {
		name         string
		testFunction func(jwt string) error
	}{
		{
			name: "AddUserWithJWTToTeamWithID",
			testFunction: func(jwt string) error {
				err := setup.tService.AddUserWithJWTToTeamWithID(context.Background(), jwt, "")
				return err
			},
		},
		{
			name: "RemoveUserWithJWTFromTheirTeam",
			testFunction: func(jwt string) error {
				err := setup.tService.RemoveUserWithJWTFromTheirTeam(context.Background(), jwt)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidToken, tt.testFunction("invalid token"))
		})
	}
}

func Test_CreateTeam__should_return_ErrNameTaken_when_email_is_taken(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	_, err := setup.tRepo.InsertOne(context.Background(), testTeam)
	assert.NoError(t, err)

	team, err := setup.tService.CreateTeam(context.Background(), testTeam.Name, testTeam.Creator.Hex())

	assert.Equal(t, services.ErrNameTaken, err)
	assert.Nil(t, team)
}

func Test_CreateTeam__should_create_correct_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	team, err := setup.tService.CreateTeam(context.Background(), testTeam.Name, testTeam.Creator.Hex())
	assert.NoError(t, err)

	res := setup.tRepo.FindOne(context.Background(), bson.M{
		string(entities.TeamID):      team.ID,
		string(entities.TeamName):    testTeam.Name,
		string(entities.TeamCreator): testTeam.Creator,
	})

	assert.NoError(t, res.Err())
}

func Test_GetTeams__should_return_expected_teams(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testTeam2 := testTeam
	testTeam2.ID = primitive.NewObjectID()
	testTeam2.Name = "Team of Robs"

	testTeams := []entities.Team{testTeam, testTeam2}

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam, testTeam2})
	assert.NoError(t, err)

	teams, err := setup.tService.GetTeams(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, testTeams, teams)
}

func Test_GetTeamWithID__should_return_ErrNotFound_when_team_with_id_doesnt_exist(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	team, err := setup.tService.GetTeamWithID(context.Background(), primitive.NewObjectID().Hex())

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, team)
}

func Test_GetTeamWithID__should_return_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testTeam2 := testTeam
	testTeam2.ID = primitive.NewObjectID()
	testTeam2.Name = "Team of Robs"

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam, testTeam2})
	assert.NoError(t, err)

	team, err := setup.tService.GetTeamWithID(context.Background(), testTeam2.ID.Hex())

	assert.NoError(t, err)
	assert.Equal(t, testTeam2, *team)
}

func Test_GetTeamWithName__should_return_ErrNotFound_when_team_with_name_doesnt_exist(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	team, err := setup.tService.GetTeamWithName(context.Background(), testTeam.Name)

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, team)
}

func Test_GetTeamWithName__should_return_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testTeam2 := testTeam
	testTeam2.ID = primitive.NewObjectID()
	testTeam2.Name = "Team of Robs"

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam, testTeam2})
	assert.NoError(t, err)

	team, err := setup.tService.GetTeamWithName(context.Background(), testTeam2.Name)

	assert.NoError(t, err)
	assert.Equal(t, testTeam2, *team)
}

func Test_GetTeamForUserWithID__should_return_error_when_GetUserWithID_returns_error(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	userID := primitive.NewObjectID().Hex()

	setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), userID).Return(nil, services.ErrNotFound).Times(1)

	team, err := setup.tService.GetTeamForUserWithID(context.Background(), userID)

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, team)
}

func Test_GetTeamForUserWithID__should_return_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	userID := primitive.NewObjectID().Hex()

	setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), userID).Return(&entities.User{
		Team: testTeam.ID,
	}, nil).Times(1)

	_, err := setup.tRepo.InsertOne(context.Background(), testTeam)
	assert.NoError(t, err)

	team, err := setup.tService.GetTeamForUserWithID(context.Background(), userID)

	assert.NoError(t, err)
	assert.Equal(t, testTeam, *team)
}

func Test_GetTeamForUserWithEmail__should_return_error_when_GetUserWithEmail_returns_error(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	setup.mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "test@email.com").Return(nil, services.ErrNotFound).Times(1)

	team, err := setup.tService.GetTeamForUserWithEmail(context.Background(), "test@email.com")

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, team)
}

func Test_GetTeamForUserWithEmail__should_return_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	setup.mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "test@email.com").Return(&entities.User{
		Team: testTeam.ID,
	}, nil).Times(1)

	_, err := setup.tRepo.InsertOne(context.Background(), testTeam)
	assert.NoError(t, err)

	team, err := setup.tService.GetTeamForUserWithEmail(context.Background(), "test@email.com")

	assert.NoError(t, err)
	assert.Equal(t, testTeam, *team)
}

func Test_GetTeamForUserWithJWT__should_return_error_when_GetUserWithEmail_returns_error(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "some token").Return(nil, services.ErrNotFound).Times(1)

	team, err := setup.tService.GetTeamForUserWithJWT(context.Background(), "some token")

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, team)
}

func Test_GetTeamForUserWithJWT__should_return_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "some token").Return(&entities.User{
		Team: testTeam.ID,
	}, nil).Times(1)

	_, err := setup.tRepo.InsertOne(context.Background(), testTeam)
	assert.NoError(t, err)

	team, err := setup.tService.GetTeamForUserWithJWT(context.Background(), "some token")

	assert.NoError(t, err)
	assert.Equal(t, testTeam, *team)
}

func Test_DeleteTeamWithID__should_return_ErrNotFound_when_team_with_id_doesnt_exist(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	err := setup.tService.DeleteTeamWithID(context.Background(), testTeam.ID.Hex())

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_DeleteTeamWithID__should_delete_expected_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testTeam2 := testTeam
	testTeam2.ID = primitive.NewObjectID()
	testTeam2.Name = "Team of Robs"

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam, testTeam2})
	assert.NoError(t, err)

	err = setup.tService.DeleteTeamWithID(context.Background(), testTeam.ID.Hex())
	assert.NoError(t, err)

	cur, err := setup.tRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	teams, err := decodeTeamsResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Equal(t, []entities.Team{testTeam2}, teams)
}

func Test_AddUserWithIDToTeamWithID__should_add_correct_user_to_correct_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testUser2 := testUser
	testUser2.Team = primitive.NilObjectID

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam})
	assert.NoError(t, err)

	setup.mockUService.EXPECT().GetUserWithID(context.Background(), "testid").
		Return(&testUser2, nil).Times(1)

	setup.mockUService.EXPECT().UpdateUserWithID(context.Background(), "testid", services.UserUpdateParams{
		entities.UserTeam: testTeam.ID,
	})

	err = setup.tService.AddUserWithIDToTeamWithID(context.Background(), "testid", testTeam.ID.Hex())
	assert.NoError(t, err)
}

func Test_AddUserWithIDToTeamWithID__should_return_err_when_user_is_already_in_a_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testUser2 := testUser
	testUser2.Team = primitive.NewObjectID()

	setup.mockUService.EXPECT().GetUserWithID(context.Background(), "testid").
		Return(&testUser2, nil).Times(1)

	err := setup.tService.AddUserWithIDToTeamWithID(context.Background(), "testid", testTeam.ID.Hex())
	assert.Error(t, err)
}

func Test_RemoveUserWithIDFromTheirTeam__should_remove_correct_user_from_team_and_delete_empty_team(t *testing.T) {
	setup := setupTeamTest(t)
	defer setup.cleanup()

	testTeam2 := testTeam
	testTeam2.ID = primitive.NewObjectID()

	testUser2 := testUser
	testUser2.Team = testTeam2.ID

	_, err := setup.tRepo.InsertMany(context.Background(), []interface{}{testTeam2})
	assert.NoError(t, err)

	setup.mockUService.EXPECT().GetUserWithID(context.Background(), "testid").
		Return(&testUser2, nil).Times(1)
	setup.mockUService.EXPECT().UpdateUserWithID(context.Background(), "testid", services.UserUpdateParams{
		entities.UserTeam: primitive.NilObjectID,
	})
	setup.mockUService.EXPECT().GetUsersWithTeam(context.Background(), testTeam2.ID.Hex()).Return(nil, nil).Times(1)

	err = setup.tService.RemoveUserWithIDFromTheirTeam(context.Background(), "testid")
	assert.NoError(t, err)

	cur, err := setup.tRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	teams, err := decodeTeamsResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Nil(t, teams)
}
