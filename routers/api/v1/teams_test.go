package v1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type teamsTestSetup struct {
	mockEService *mock_services.MockEmailService
	mockTService *mock_services.MockTeamService
	mockUService *mock_services.MockUserService
	env          *environment.Env
	router       APIV1Router
	testServer   *gin.Engine
	w            *httptest.ResponseRecorder
	testCtx      *gin.Context
	testUser     *entities.User
	testTeam     *entities.Team
	claims       *auth.Claims
	jwt          string
}

func setupTeamsTest(t *testing.T, envVars map[string]string) *teamsTestSetup {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockEService := mock_services.NewMockEmailService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)

	restore := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restore()

	router := NewAPIV1Router(zap.NewNop(), &config.AppConfig{
		BaseAuthLevel:     baseTestAuthLevel,
		AuthTokenLifetime: testAuthTokenLifetime,
	}, env, mockUService, mockEService, mockTService)

	userID := primitive.NewObjectID()

	testTeam := entities.Team{
		ID:      primitive.ObjectID{},
		Name:    "",
		Creator: userID,
	}

	testUser := entities.User{
		ID:        userID,
		Name:      "Bob the Tester",
		Email:     "test@email.com",
		AuthLevel: baseTestAuthLevel,
		Team:      testTeam.ID,
		Password:  "password123",
	}

	jwt, _ := auth.NewJWT(testUser, time.Now().Unix(), testAuthTokenLifetime, auth.Auth, []byte(env.Get(environment.JWTSecret)))
	claims := auth.GetJWTClaims(jwt, []byte(env.Get(environment.JWTSecret)))

	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)

	return &teamsTestSetup{
		mockUService: mockUService,
		mockEService: mockEService,
		mockTService: mockTService,
		testUser:     &testUser,
		testTeam:     &testTeam,
		env:          env,
		router:       router,
		testServer:   testServer,
		w:            w,
		testCtx:      testCtx,
		claims:       claims,
		jwt:          jwt,
	}
}

func Test_GetTeams(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *teamsTestSetup)
		wantResCode int
		wantRes     *getTeamsRes
	}{
		{
			name: "should return 500 when fetching teams fails",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeams(gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and expected teams",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeams(gomock.Any()).
					Return([]entities.Team{
						{Name: "Team of bobs"},
						{Name: "Team of robs"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamsRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Teams: []entities.Team{
					{Name: "Team of bobs"},
					{Name: "Team of robs"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetTeams(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getTeamsRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_CreateTeam(t *testing.T) {
	tests := []struct {
		name          string
		prep          func(setup *teamsTestSetup)
		givenTeamName string
		wantResCode   int
		jwt           string
		wantRes       *createTeamRes
	}{
		{
			name:        "should return 400 when team name is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:          "should pass correct jwt to team service",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), gomock.Any(), "testjwt").
					Return(&entities.Team{}, nil).Times(1)
			},
			jwt:         "testjwt",
			wantResCode: http.StatusOK,
		},
		{
			name:          "should return 401 when team service returns ErrInvalidToken",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", gomock.Any()).
					Return(nil, services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:          "should return 400 when team service returns ErrNotFound",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", gomock.Any()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:          "should return 400 when team service returns ErrUserInTeam",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", gomock.Any()).
					Return(nil, services.ErrUserInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:          "should return 500 when team service returns unknown error",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:          "should return 200 when team service does not return error",
			givenTeamName: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", gomock.Any()).
					Return(&entities.Team{Name: "testteam"}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &createTeamRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Team: entities.Team{Name: "testteam"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
				http.MethodPost,
				map[string]string{
					"name": tt.givenTeamName,
				})
			setup.testCtx.Request.Header.Set(authHeaderName, tt.jwt)

			setup.router.CreateTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes createTeamRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_LeaveTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *teamsTestSetup)
		jwt         string
		wantResCode int
		wantRes     *models.Response
	}{
		{
			name: "should pass correct jwt to team service",
			jwt:  "testjwt",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "testjwt").
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name: "should return 401 when team service returns ErrInvalidToken",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), gomock.Any()).
					Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when team service returns ErrNotFound",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), gomock.Any()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when team service returns ErrUserNotInTeam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), gomock.Any()).
					Return(services.ErrUserNotInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when team service returns unknown error",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when team service does not return error",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &models.Response{
				Status: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodDelete, nil)
			setup.testCtx.Request.Header.Set(authHeaderName, tt.jwt)

			setup.router.LeaveTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes models.Response
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_JoinTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *teamsTestSetup)
		jwt         string
		givenTeamID string
		wantResCode int
		wantRes     *models.Response
	}{
		{
			name:        "should return 400 when no team id is given",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should pass correct jwt to team service",
			jwt:         "testjwt",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), "testjwt", gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:        "should return 401 when team service returns ErrInvalidToken",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:        "should return 400 when team service returns ErrInvalidID",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when team service returns ErrNotFound",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when team service returns ErrUserInTeam",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(services.ErrUserInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 500 when team service returns unknown error",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:        "should return 200 when team service does not return error",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), gomock.Any(), "testteam").
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &models.Response{
				Status: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, nil)
			setup.testCtx.Request.Header.Set(authHeaderName, tt.jwt)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{
				"id": tt.givenTeamID,
			})

			setup.router.JoinTeam(setup.testCtx)
			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes models.Response
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_GetTeamMembers(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *teamsTestSetup)
		givenTeamID string
		wantResCode int
		wantRes     *getTeamMembersRes
	}{
		{
			name:        "should return 400 when no team id is given",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when user service returns ErrInvalidID",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), gomock.Any()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 500 when user service returns unknown error",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:        "should return 200 and expected team members",
			givenTeamID: "testteam",
			prep: func(setup *teamsTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), gomock.Any()).
					Return([]entities.User{
						{Name: "Bob the Tester"},
						{Name: "Rob the Tester"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamMembersRes{
				Response: models.Response{
					Status: http.StatusOK,
				},
				Users: []entities.User{
					{Name: "Bob the Tester"},
					{Name: "Rob the Tester"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{
				"id": tt.givenTeamID,
			})

			setup.router.GetTeamMembers(setup.testCtx)
			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getTeamMembersRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}
