package v2

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

type teamsTestSetup struct {
	ctrl           *gomock.Controller
	router         APIV2Router
	mockAuthorizer *mock_v2.MockAuthorizer
	mockTService   *mock_services.MockTeamService
	testTeam       *entities.Team
	testCtx        *gin.Context
	w              *httptest.ResponseRecorder
}

func setupTeamsTest(t *testing.T) *teamsTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)

	router := NewAPIV2Router(zap.NewNop(), &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}, mockAuthorizer, nil, mockTService, nil, nil, mockTimeProvider)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	testTeam := entities.Team{
		ID:      testTeamId,
		Name:    "Bobs the Testers",
		Creator: testUserId,
	}

	return &teamsTestSetup{
		ctrl:           ctrl,
		router:         router,
		mockAuthorizer: mockAuthorizer,
		testCtx:        testCtx,
		w:              w,
		testTeam:       &testTeam,
		mockTService:   mockTService,
	}
}

func TestApiV2Router_GetTeams(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *teamsTestSetup)
		wantResCode int
		wantRes     *getTeamsRes
	}{
		{
			name: "should return 500 when team service returns error",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeams(setup.testCtx).Return(nil, errors.New("service err")).
					Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and expected teams",
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeams(setup.testCtx).Return([]entities.Team{
					{
						Name: "Bobs the Testers",
					},
					{
						Name: "Robs the Testers",
					},
				}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamsRes{
				Teams: []entities.Team{
					{
						Name: "Bobs the Testers",
					},
					{
						Name: "Robs the Testers",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t)
			defer setup.ctrl.Finish()
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

func TestApiV2Router_GetTeam(t *testing.T) {
	tests := []struct {
		name        string
		teamId      string
		prep        func(setup *teamsTestSetup)
		wantResCode int
		wantRes     *getTeamRes
	}{
		{
			name:   "should return 401 when user id is me and authorizer returns ErrInvalidToken",
			teamId: "me",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			teamId: "me",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when user id is me and authorizer returns unknown err",
			teamId: "me",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("some err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 when team service returns ErrInvalidID",
			teamId: testTeamId.Hex(),
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(setup.testCtx, testTeamId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when team service returns ErrNotFound",
			teamId: testTeamId.Hex(),
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(setup.testCtx, testTeamId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:   "should return 500 when team service returns unknown error",
			teamId: testTeamId.Hex(),
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(setup.testCtx, testTeamId.Hex()).
					Return(nil, errors.New("some err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 and correct team when team id is specified",
			teamId: testTeamId.Hex(),
			prep: func(setup *teamsTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(setup.testCtx, testTeamId.Hex()).
					Return(setup.testTeam, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamRes{
				Team: entities.Team{
					ID:      testTeamId,
					Name:    "Bobs the Testers",
					Creator: testUserId,
				},
			},
		},
		{
			name:   "should return 200 and correct user when user id is me",
			teamId: "me",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testTeam, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeamRes{
				Team: entities.Team{
					ID:      testTeamId,
					Name:    "Bobs the Testers",
					Creator: testUserId,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.teamId})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getTeamRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func TestApiV2Router_CreateTeam(t *testing.T) {
	tests := []struct {
		name        string
		teamName    string
		prep        func(setup *teamsTestSetup)
		wantResCode int
		wantRes     *createTeamRes
	}{
		{
			name:        "should return 400 when team name is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 401 when authorizer.GetTokenTypeFromToken returns ErrInvalidToken",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.TokenType(""), v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 401 when authorizer.GetTokenTypeFromToken returns unknown error",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.TokenType(""), errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 400 when token type is service and CreateTeam returns ErrInvalidID",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.Service, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeam(setup.testCtx, "Bobs_the_Testers", primitive.NilObjectID.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when token type is service and CreateTeam returns ErrNameTaken",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.Service, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeam(setup.testCtx, "Bobs_the_Testers", primitive.NilObjectID.Hex()).
					Return(nil, services.ErrNameTaken).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when token type is service and CreateTeam returns unknown error",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.Service, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeam(setup.testCtx, "Bobs_the_Testers", primitive.NilObjectID.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 401 when token type is user and GetUserIdFromToken returns ErrInvalidToken",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 400 when token type is user and GetUserIdFromToken returns ErrInvalidTokenType",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when token type is user and GetUserIdFromToken returns unknown error",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 400 when token type is user and CreateTeamForUserWithID returns ErrInvalidID",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeamForUserWithID(setup.testCtx, "Bobs_the_Testers", testUserId.Hex()).
					Return(nil, services.ErrInvalidID)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when token type is user and CreateTeamForUserWithID returns ErrNameTaken",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeamForUserWithID(setup.testCtx, "Bobs_the_Testers", testUserId.Hex()).
					Return(nil, services.ErrNameTaken)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when token type is user and CreateTeamForUserWithID returns ErrUserInTeam",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeamForUserWithID(setup.testCtx, "Bobs_the_Testers", testUserId.Hex()).
					Return(nil, services.ErrUserInTeam)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when token type is user and CreateTeamForUserWithID returns unknown error",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeamForUserWithID(setup.testCtx, "Bobs_the_Testers", testUserId.Hex()).
					Return(nil, errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 and expected team when token type is service",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.Service, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeam(setup.testCtx, "Bobs_the_Testers", primitive.NilObjectID.Hex()).
					Return(setup.testTeam, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &createTeamRes{
				Team: entities.Team{
					ID:      testTeamId,
					Name:    "Bobs the Testers",
					Creator: testUserId,
				},
			},
		},
		{
			name:     "should return 200 and expected team when token type is user",
			teamName: "Bobs_the_Testers",
			prep: func(setup *teamsTestSetup) {
				setup.mockAuthorizer.EXPECT().GetTokenTypeFromToken(testAuthToken).
					Return(v2.User, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().CreateTeamForUserWithID(setup.testCtx, "Bobs_the_Testers", testUserId.Hex()).
					Return(setup.testTeam, nil)
			},
			wantResCode: http.StatusOK,
			wantRes: &createTeamRes{
				Team: entities.Team{
					ID:      testTeamId,
					Name:    "Bobs the Testers",
					Creator: testUserId,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTeamsTest(t)
			defer setup.ctrl.Finish()
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{"name": tt.teamName})
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			if tt.prep != nil {
				tt.prep(setup)
			}

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
