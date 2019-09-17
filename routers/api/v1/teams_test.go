package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/unicsmcr/hs_auth/services"

	"github.com/stretchr/testify/assert"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/unicsmcr/hs_auth/utils/auth"

	"github.com/unicsmcr/hs_auth/config"

	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"

	"github.com/golang/mock/gomock"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
)

type testSetup struct {
	mockUService *mock_services.MockUserService
	mockTService *mock_services.MockTeamService
	mockEService *mock_services.MockEmailService
	env          *environment.Env
	router       APIV1Router
	testUser     *entities.User
	w            *httptest.ResponseRecorder
	testCtx      *gin.Context
	testServer   *gin.Engine
	claims       *auth.Claims
	emailToken   string
}

func setupTeamTest(t *testing.T, envVars map[string]string, authLevel common.AuthLevel) *testSetup {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)

	restore := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restore()

	router := NewAPIV1Router(zap.NewNop(), &config.AppConfig{
		BaseAuthLevel: 0,
	}, mockUService, nil, mockTService, env)

	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		Name:      "John Doe",
		Email:     "john@doe.com",
		AuthLevel: authLevel,
		Team:      primitive.NewObjectID(),
	}

	claims := &auth.Claims{
		StandardClaims: jwt.StandardClaims{
			Id: testUser.ID.Hex(),
		},
		AuthLevel: testUser.AuthLevel,
	}

	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	testCtx.Set(authClaimsKeyInCtx, claims)

	return &testSetup{
		mockUService: mockUService,
		mockTService: mockTService,
		env:          env,
		router:       router,
		testUser:     &testUser,
		w:            w,
		testCtx:      testCtx,
		testServer:   testServer,
		claims:       claims,
	}
}

func Test_GetTeams(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		wantResCode int
		wantRes     *getTeamsRes
	}{
		{
			name: "should return 500 when fetching teams fails",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeams(gomock.Any()).Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and the correct teams",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeams(gomock.Any()).Return([]entities.Team{
					{Name: "test team 1"},
					{Name: "test team 2"},
				}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamsRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Teams: []entities.Team{
					{Name: "test team 1"},
					{Name: "test team 2"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamTest(t, nil, 0)
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetTeams(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				actualResStr, err := setup.w.Body.ReadString('\x00')
				assert.Equal(t, "EOF", err.Error())

				var actualRes getTeamsRes
				err = json.Unmarshal([]byte(actualResStr), &actualRes)

				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_CreateTeam(t *testing.T) {
	tests := []struct {
		name        string
		teamName    string
		prep        func(*testSetup)
		wantResCode int
	}{
		{
			name:        "should return 400 when no team name is provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when there are no auth claim in request's context",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.testCtx.Set(authClaimsKeyInCtx, nil)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when user in auth claims doesn't exist",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when query for user with id fails",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 400 when user is already in a team",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{Team: primitive.NewObjectID()}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when team name is taken",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithName(gomock.Any(), "test team 1").
					Return(nil, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when query for team with name fails",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithName(gomock.Any(), "test team 1").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 500 when query to create team fails",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithName(gomock.Any(), "test team 1").
					Return(nil, services.ErrNotFound).Times(1)
				setup.mockTService.EXPECT().CreateTeam(gomock.Any(), "test team 1", setup.testUser.ID.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 500 and try to delete new team when query to add user to new team fails",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithName(gomock.Any(), "test team 1").
					Return(nil, services.ErrNotFound).Times(1)
				team := entities.Team{ID: primitive.NewObjectID()}
				setup.mockTService.EXPECT().CreateTeam(gomock.Any(), "test team 1", setup.testUser.ID.Hex()).
					Return(&team, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": team.ID,
				}).Return(errors.New("service err")).Times(1)
				setup.mockTService.EXPECT().DeleteTeamWithID(gomock.Any(), team.ID.Hex()).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when team gets created and user gets added to the new team",
			teamName: "test team 1",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithName(gomock.Any(), "test team 1").
					Return(nil, services.ErrNotFound).Times(1)
				team := entities.Team{ID: primitive.NewObjectID()}
				setup.mockTService.EXPECT().CreateTeam(gomock.Any(), "test team 1", setup.testUser.ID.Hex()).
					Return(&team, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": team.ID,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamTest(t, nil, 0)
			if tt.prep != nil {
				tt.prep(setup)
			}

			data := url.Values{}
			data.Add("name", tt.teamName)

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			setup.testCtx.Request = req

			setup.router.CreateTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_LeaveTeam(t *testing.T) {
	tests := []struct {
		name        string
		teamID      string
		prep        func(*testSetup)
		wantResCode int
	}{
		{
			name: "should return 400 if request context is missing auth claims",
			prep: func(setup *testSetup) {
				setup.testCtx.Set(authClaimsKeyInCtx, nil)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 if query for user with id fails",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 400 if user is not in a team",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{Team: primitive.NilObjectID}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 if query for team with id fails",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 500 if removing the user from the team fails when the user is not the team's creator",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(&entities.Team{
						Creator: primitive.NewObjectID(),
					}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": primitive.NilObjectID,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when removing a user from a team is successful and the user is not the team's creator",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(&entities.Team{
						Creator: primitive.NewObjectID(),
					}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": primitive.NilObjectID,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name: "should return 500 when removing all team's members from the team fails",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(&entities.Team{
						ID:      setup.testUser.Team,
						Creator: setup.testUser.ID,
					}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUsersWithTeam(gomock.Any(), setup.testUser.Team.Hex(), map[string]interface{}{
					"team": primitive.NilObjectID,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 500 when deleting team fails",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(&entities.Team{
						ID:      setup.testUser.Team,
						Creator: setup.testUser.ID,
					}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUsersWithTeam(gomock.Any(), setup.testUser.Team.Hex(), map[string]interface{}{
					"team": primitive.NilObjectID,
				}).Return(nil).Times(1)
				setup.mockTService.EXPECT().DeleteTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when team creator leaves team",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(&entities.Team{
						ID:      setup.testUser.Team,
						Creator: setup.testUser.ID,
					}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUsersWithTeam(gomock.Any(), setup.testUser.Team.Hex(), map[string]interface{}{
					"team": primitive.NilObjectID,
				}).Return(nil).Times(1)
				setup.mockTService.EXPECT().DeleteTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamTest(t, nil, 0)
			if len(tt.teamID) > 0 {
				teamID, _ := primitive.ObjectIDFromHex(tt.teamID)
				setup.testUser.Team = teamID
			}
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.LeaveTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_JoinTeam(t *testing.T) {
	tests := []struct {
		name        string
		teamID      string
		prep        func(*testSetup)
		wantResCode int
	}{
		{
			name:        "should return 400 when team id is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 if invalid team id is provided",
			teamID:      "5d7fd41d14ee34754",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 if request context is missing auth claims",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.testCtx.Set(authClaimsKeyInCtx, nil)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when query for user fails",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 if user already has a team",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 if team with given id doesn't exist",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.testUser.Team = primitive.NilObjectID
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 if query for team fails",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.testUser.Team = primitive.NilObjectID
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 500 if query for to update user's team fails",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				teamID := setup.testUser.Team
				setup.testUser.Team = primitive.NilObjectID
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": teamID,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 if everything goes well",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				teamID := setup.testUser.Team
				setup.testUser.Team = primitive.NilObjectID
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": teamID,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamTest(t, nil, 0)
			teamID, _ := primitive.ObjectIDFromHex(tt.teamID)
			setup.testUser.Team = teamID
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.testCtx.Params = gin.Params{
				gin.Param{Key: "id", Value: tt.teamID},
			}

			setup.router.JoinTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_GetTeamMembers(t *testing.T) {
	tests := []struct {
		name        string
		teamID      string
		authLevel   common.AuthLevel
		prep        func(*testSetup)
		wantRes     *getTeamMembersRes
		wantResCode int
	}{
		{
			name:        "should return 400 when team id is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 if request context is missing auth claims",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.testCtx.Set(authClaimsKeyInCtx, nil)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when user is not organizer and query to get user fails",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 when user is not organizer and they are in a different team",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(&entities.User{Team: primitive.NewObjectID()}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:      "should return 400 when given team id is invalid",
			authLevel: common.Organizer,
			teamID:    "5d7fd41dcccdb2114",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), "5d7fd41dcccdb2114").
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:      "should return 400 when team with given id doesn't exist",
			authLevel: common.Organizer,
			teamID:    "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:      "should return 500 when query to get users fails",
			authLevel: common.Organizer,
			teamID:    "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:      "should return 200 and expected response when user is organizer",
			authLevel: common.Organizer,
			teamID:    "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return([]entities.User{
						{Name: "John Doe"},
						{Name: "Jane Doe"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamMembersRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Users: []entities.User{
					{Name: "John Doe"},
					{Name: "Jane Doe"},
				},
			},
		},
		{
			name:   "should return 200 and expected response when user is not organizer",
			teamID: "5d7fd41dcccdb2114ee34754",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), "5d7fd41dcccdb2114ee34754").
					Return([]entities.User{
						{Name: "John Doe"},
						{Name: "Jane Doe"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamMembersRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Users: []entities.User{
					{Name: "John Doe"},
					{Name: "Jane Doe"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamTest(t, nil, 0)
			teamID, _ := primitive.ObjectIDFromHex(tt.teamID)
			setup.testUser.Team = teamID
			setup.claims.AuthLevel = tt.authLevel
			setup.testCtx.Set(authClaimsKeyInCtx, setup.claims)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.testCtx.Params = gin.Params{
				gin.Param{Key: "id", Value: tt.teamID},
			}

			setup.router.GetTeamMembers(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				actualResStr, err := ioutil.ReadAll(setup.w.Body)
				assert.NoError(t, err)

				var actualRes getTeamMembersRes
				err = json.Unmarshal([]byte(actualResStr), &actualRes)

				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}
