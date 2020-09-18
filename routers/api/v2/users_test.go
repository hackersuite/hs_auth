package v2

import (
	"errors"
	"fmt"
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
	"time"
)

const (
	testAuthTokenLifetime = 10000000
	testAuthToken         = "authToken"
)

var (
	testUserId = primitive.NewObjectID()
	testTeamId = primitive.NewObjectID()
)

type usersTestSetup struct {
	ctrl             *gomock.Controller
	router           APIV2Router
	mockUService     *mock_services.MockUserService
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	testUser         *entities.User
	testCtx          *gin.Context
	w                *httptest.ResponseRecorder
}

func setupUsersTest(t *testing.T) *usersTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	router := NewAPIV2Router(zap.NewNop(), &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}, mockAuthorizer, mockUService, nil, nil, mockTimeProvider)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	testUser := entities.User{
		ID:       testUserId,
		Name:     "Bob the Tester",
		Email:    "test@email.com",
		Team:     testTeamId,
		Password: "password123",
	}

	return &usersTestSetup{
		ctrl:             ctrl,
		router:           router,
		mockUService:     mockUService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		testUser:         &testUser,
		testCtx:          testCtx,
		w:                w,
	}
}

func TestApiV2Router_Login(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		prep        func(*usersTestSetup)
		wantResCode int
		wantRes     *loginRes
		jwtSecret   string
	}{
		{
			name:        "should return 400 when email is not provided",
			password:    "password123",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when password is not provided",
			email:       "test@email.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 401 when user service returns ErrNotFound",
			email:       "test@email.com",
			password:    "password123",
			wantResCode: http.StatusUnauthorized,
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
					Return(nil, services.ErrNotFound).Times(1)
			},
		},
		{
			name:        "should return 500 when user service returns unknown error",
			email:       "test@email.com",
			password:    "password123",
			wantResCode: http.StatusInternalServerError,
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
					Return(nil, errors.New("service err")).Times(1)
			},
		},
		{
			name:        "should return 500 when creating token fails",
			email:       "test@email.com",
			password:    "password123",
			wantResCode: http.StatusInternalServerError,
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
					Return(setup.testUser, nil).Times(1)
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(0, 0)).Times(1)
				setup.mockAuthorizer.EXPECT().CreateUserToken(setup.testUser.ID, int64(testAuthTokenLifetime)).
					Return("", errors.New("authorizer err")).Times(1)
			},
		},
		{
			name:     "should return 200 and correct token when logging in succeeds",
			email:    "test@email.com",
			password: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
					Return(setup.testUser, nil).Times(1)
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(0, 0)).Times(1)
				setup.mockAuthorizer.EXPECT().CreateUserToken(setup.testUser.ID, int64(testAuthTokenLifetime)).
					Return("test_token", nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &loginRes{
				Token: "test_token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
				http.MethodPost,
				map[string]string{
					"email":    tt.email,
					"password": tt.password,
				},
			)

			setup.router.Login(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes loginRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func TestApiV2Router_Register(t *testing.T) {
	tests := []struct {
		name         string
		prep         func(*usersTestSetup)
		testName     string
		testEmail    string
		testPassword string
		wantResCode  int
	}{
		{
			name:         "should return 400 when name is not provided",
			testEmail:    "test@email.com",
			testPassword: "password123",
			wantResCode:  http.StatusBadRequest,
		},
		{
			name:         "should return 400 when email is not provided",
			testName:     "Bob the Tester",
			testPassword: "password123",
			wantResCode:  http.StatusBadRequest,
		},
		{
			name:        "should return 400 when password is not provided",
			testName:    "Bob the Tester",
			testEmail:   "test@email.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:         "should return 400 when user service returns ErrEmailTaken",
			testName:     "Bob the Tester",
			testEmail:    "test@email.com",
			testPassword: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123").
					Return(nil, services.ErrEmailTaken).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:         "should return 500 when user service returns unknown error",
			testName:     "Bob the Tester",
			testEmail:    "test@email.com",
			testPassword: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:         "should return 200 and expected result",
			testName:     "Bob the Tester",
			testEmail:    "test@email.com",
			testPassword: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123").
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
				http.MethodPost,
				map[string]string{
					"name":     tt.testName,
					"email":    tt.testEmail,
					"password": tt.testPassword,
				},
			)

			setup.router.Register(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestApiV2Router_GetUsers(t *testing.T) {
	tests := []struct {
		name        string
		teamId      string
		prep        func(*usersTestSetup)
		wantResCode int
		wantRes     *getUsersRes
	}{
		{
			name: "should return 500 when team id not specified and users service returns err",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).Return(nil, errors.New("service err")).
					Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 401 when team id is me and authorizer returns ErrInvalidToken",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when team id is me and authorizer returns ErrInvalidTokenType",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when team id is me and user service returns ErrInvalidID",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetTeamMembersForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when team id is me and user service returns ErrNotFound",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetTeamMembersForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:   "should return 400 when team id is me and user service returns ErrUserNotInTeam",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetTeamMembersForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrUserNotInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when team id is me and user service returns unknown error",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetTeamMembersForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 when team id is specified and user service returns ErrInvalidId",
			teamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(setup.testCtx, testTeamId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when team id is specified and user service returns unknown error",
			teamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(setup.testCtx, testTeamId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 and expected result when team id is me",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetTeamMembersForUserWithID(setup.testCtx, testUserId.Hex()).
					Return([]entities.User{
						{
							Name: "Bob the Tester",
						},
						{
							Name: "Rob the Tester",
						},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUsersRes{
				Users: []entities.User{
					{
						Name: "Bob the Tester",
					},
					{
						Name: "Rob the Tester",
					},
				},
			},
		},
		{
			name:   "should return 200 and expected result when team id is specified",
			teamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(setup.testCtx, testTeamId.Hex()).
					Return([]entities.User{
						{
							Name: "Bob the Tester",
						},
						{
							Name: "Rob the Tester",
						},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUsersRes{
				Users: []entities.User{
					{
						Name: "Bob the Tester",
					},
					{
						Name: "Rob the Tester",
					},
				},
			},
		},
		{
			name: "should return 200 and expected result when team id not specified",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).Return([]entities.User{
					{
						Name: "Bob the Tester",
					},
					{
						Name: "Rob the Tester",
					},
				}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUsersRes{
				Users: []entities.User{
					{
						Name: "Bob the Tester",
					},
					{
						Name: "Rob the Tester",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			defer setup.ctrl.Finish()
			var req *http.Request
			if tt.teamId != "" {
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/test?team=%s", tt.teamId), nil)
			} else {
				req = httptest.NewRequest(http.MethodGet, "/test", nil)
			}
			setup.testCtx.Request = req
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetUsers(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getUsersRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func TestApiV2Router_GetUser(t *testing.T) {
	tests := []struct {
		name        string
		userId      string
		prep        func(*usersTestSetup)
		wantResCode int
		wantRes     *getUserRes
	}{
		{
			name:   "should return 401 when user id is me and authorizer returns ErrInvalidToken",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when user id is me and authorizer returns unknown err",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("some err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 when user service returns ErrInvalidID",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when user service returns ErrNotFound",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:   "should return 500 when user service returns unknown error",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("some err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 and correct user when user id is specified",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUserRes{
				User: entities.User{
					ID:       testUserId,
					Name:     "Bob the Tester",
					Email:    "test@email.com",
					Team:     testTeamId,
					Password: "",
				},
			},
		},
		{
			name:   "should return 200 and correct user when user id is me",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUserRes{
				User: entities.User{
					ID:       testUserId,
					Name:     "Bob the Tester",
					Email:    "test@email.com",
					Team:     testTeamId,
					Password: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.userId})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetUser(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getUserRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func TestApiV2Router_SetPassword(t *testing.T) {
	tests := []struct {
		name        string
		userId      string
		password    string
		prep        func(*usersTestSetup)
		wantResCode int
	}{
		{
			name:        "should return 400 when password not included in request",
			userId:      "me",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 401 when user id is me and authorizer returns ErrInvalidToken",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, v2.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when user id is me and authorizer returns ErrInvalidID",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 404 when user id is me and authorizer returns ErrNotFound",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:     "should return 500 when user id is me and authorizer returns unknown err",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("some err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 400 when user service returns ErrInvalidID",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().
					ResetPasswordForUserWithIDAndEmail(setup.testCtx, testUserId.Hex(), setup.testUser.Email, "test").
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 404 when user service returns StatusNotFound",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().
					ResetPasswordForUserWithIDAndEmail(setup.testCtx, testUserId.Hex(), setup.testUser.Email, "test").
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:     "should return 500 when user service returns unknown error",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().
					ResetPasswordForUserWithIDAndEmail(setup.testCtx, testUserId.Hex(), setup.testUser.Email, "test").
					Return(errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when user id is me",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().
					ResetPasswordForUserWithIDAndEmail(setup.testCtx, testUserId.Hex(), setup.testUser.Email, "test").
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200 when user id is specified",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockUService.EXPECT().
					ResetPasswordForUserWithIDAndEmail(setup.testCtx, testUserId.Hex(), setup.testUser.Email, "test").
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPut, map[string]string{
				"password": tt.password,
			})
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.userId})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.SetPassword(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}
