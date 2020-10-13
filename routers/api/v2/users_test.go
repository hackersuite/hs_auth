package v2

import (
	"context"
	"errors"
	"fmt"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services/mongo"
	"github.com/unicsmcr/hs_auth/utils"
	mongod "go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/entities"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const (
	testAuthTokenLifetime = 10000000
	testAuthToken         = "authToken"
)

var (
	testUserId     = primitive.NewObjectID()
	testTeamId     = primitive.NewObjectID()
	testRoleConfig = role.UserRoleConfig{
		role.Unverified: nil,
		role.Applicant:  nil,
		role.Attendee:   nil,
		role.Volunteer:  nil,
		role.Organiser:  nil,
	}
)

type usersTestSetup struct {
	ctrl             *gomock.Controller
	router           APIV2Router
	mockUService     *mock_services.MockUserService
	mockTService     *mock_services.MockTeamService
	mockEService     *mock_services.MockEmailServiceV2
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	testUser         *entities.User
	testCtx          *gin.Context
	w                *httptest.ResponseRecorder
}

type usersBenchmarkSetup struct {
	ctrl         *gomock.Controller
	router       APIV2Router
	timeProvider utils.TimeProvider
	testUser     *entities.User
	testCtx      *gin.Context
	w            *httptest.ResponseRecorder
	authorizer   v2.Authorizer
	uRepo        *repositories.UserRepository
	cleanup      func()
}

func setupUsersTest(t *testing.T) *usersTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)
	mockEService := mock_services.NewMockEmailServiceV2(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	router := NewAPIV2Router(zap.NewNop(), &config.AppConfig{
		UserRole: testRoleConfig,
		Auth: config.AuthConfig{
			UserTokenLifetime:         testAuthTokenLifetime,
			DefaultRole:               role.Unverified,
			DefaultEmailVerifiedRole:  role.Applicant,
			EmailVerificationRequired: true,
		},
	}, mockAuthorizer, mockUService, mockTService, nil, mockEService, mockTimeProvider)

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
		mockTService:     mockTService,
		mockEService:     mockEService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		testUser:         &testUser,
		testCtx:          testCtx,
		w:                w,
	}
}

func setupUserBenchmark(b *testing.B) *usersBenchmarkSetup {
	// Prevents gin from spamming the console output
	// Required for 'cob' benchmark result parser to work correctly
	gin.SetMode(gin.ReleaseMode)

	db := testutils.ConnectToIntegrationTestDB(b)

	userRepository, err := repositories.NewUserRepository(db)
	if err != nil {
		panic(err)
	}
	tokenRepository, err := repositories.NewTokenRepository(db)
	if err != nil {
		panic(err)
	}

	err = addBenchmarkDataToDB(db)
	if err != nil {
		panic(err)
	}

	resetEnv := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: "supersecret",
	})
	env := environment.NewEnv(zap.NewNop())
	resetEnv()

	tokenService := mongo.NewMongoTokenService(zap.NewNop(), env, tokenRepository)
	userService := mongo.NewMongoUserService(zap.NewNop(), env, &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}, userRepository)

	testCfg := &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}
	ctrl := gomock.NewController(b)
	timeProvider := utils.NewTimeProvider()
	authorizer := v2.NewAuthorizer(timeProvider, testCfg, env, zap.NewNop(), tokenService, userService)
	router := NewAPIV2Router(zap.NewNop(), testCfg, authorizer, userService, nil, tokenService, nil, timeProvider)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	testUser := entities.User{
		ID:       testUserId,
		Name:     "Bob the Tester",
		Email:    "test@email.com",
		Password: "password123",
		Team:     primitive.NewObjectID(),
	}

	return &usersBenchmarkSetup{
		ctrl:         ctrl,
		router:       router,
		timeProvider: timeProvider,
		testCtx:      testCtx,
		testUser:     &testUser,
		w:            w,
		authorizer:   authorizer,
		uRepo:        userRepository,
		cleanup: func() {
			_ = userRepository.Drop(context.Background())
			_ = tokenRepository.Drop(context.Background())
		},
	}
}

func addBenchmarkDataToDB(db *mongod.Database) error {
	userCol := db.Collection("users")
	teamCol := db.Collection("teams")
	usersToAdd := 500

	testUsers := make([]interface{}, usersToAdd)
	var testTeams []interface{}

	currentTestTeamCount := 0
	currentTestTeamID := primitive.NewObjectID()

	for i := 0; i < usersToAdd; i++ {
		nextUserID := primitive.NewObjectID()

		if currentTestTeamCount == 4 {
			currentTestTeamCount = 0
			currentTestTeamID = primitive.NewObjectID()

			testTeams = append(testTeams, entities.Team{
				ID:      currentTestTeamID,
				Name:    fmt.Sprintf("TestTeam%d", i),
				Creator: nextUserID,
			})
		}

		userTeam := primitive.ObjectID{}
		if currentTestTeamCount == 0 || len(testTeams) < usersToAdd/10 {
			userTeam = currentTestTeamID
			currentTestTeamCount++
		}

		testUsers[i] = entities.User{
			ID:       nextUserID,
			Name:     fmt.Sprintf("BenchmarkDBUser_%d", i),
			Email:    fmt.Sprintf("tester%d@email.com", i),
			Password: "pass",
			Team:     userTeam,
		}
	}

	_, err := userCol.InsertMany(context.Background(), testUsers)
	if err != nil {
		return err
	}

	_, err = teamCol.InsertMany(context.Background(), testTeams)
	if err != nil {
		return err
	}

	return nil
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123", role.Unverified).
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123", role.Unverified).
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123", role.Unverified).
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{Name: "Bob the Tester"},
					gomock.Any()).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:         "should return 200 when creating user succeeds but email verification email cannot be sent",
			testName:     "Bob the Tester",
			testEmail:    "test@email.com",
			testPassword: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123", role.Unverified).
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{Name: "Bob the Tester"},
					gomock.Any()).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusOK,
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
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when team id is me and authorizer returns ErrInvalidTokenType",
			teamId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
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
			name:   "should return 404 when team id is specified and user service returns an empty slice",
			teamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsersWithTeam(setup.testCtx, testTeamId.Hex()).
					Return(nil, nil).Times(1)
			},
			wantResCode: http.StatusNotFound,
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
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
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

func TestApiV2Router_SetTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		testUserId  string
		testTeamId  string
		wantResCode int
	}{
		{
			name:        "should return 400 when team id is not provided",
			testUserId:  testUserId.Hex(),
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 401 when authorizer.GetUserIdFromToken returns ErrInvalidToken",
			testUserId: "me",
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:       "should return 400 when authorizer.GetUserIdFromToken returns ErrInvalidTokenType",
			testUserId: "me",
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 500 when authorizer.GetUserIdFromToken returns unknown error",
			testUserId: "me",
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:       "should return 400 when teamService.AddUserWithIDToTeamWithID returns ErrInvalidID",
			testUserId: testUserId.Hex(),
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 404 when teamService.AddUserWithIDToTeamWithID returns ErrNotFound",
			testUserId: testUserId.Hex(),
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:       "should return 400 when teamService.AddUserWithIDToTeamWithID returns ErrUserInTeam",
			testUserId: testUserId.Hex(),
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(services.ErrUserInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 500 when teamService.AddUserWithIDToTeamWithID returns unknown error",
			testUserId: testUserId.Hex(),
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:       "should return 200 when user id is provided",
			testUserId: testUserId.Hex(),
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:       "should return 200 when user id is me",
			testUserId: "me",
			testTeamId: testTeamId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().AddUserWithIDToTeamWithID(setup.testCtx, testUserId.Hex(), testTeamId.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
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
					"team": tt.testTeamId,
				},
			)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.testUserId})

			setup.router.SetTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestApiV2Router_RemoveFromTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		testUserId  string
		wantResCode int
	}{
		{
			name:       "should return 401 when authorizer.GetUserIdFromToken returns ErrInvalidToken",
			testUserId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:       "should return 400 when authorizer.GetUserIdFromToken returns ErrInvalidTokenType",
			testUserId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 500 when authorizer.GetUserIdFromToken returns unknown error",
			testUserId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:       "should return 400 when teamService.RemoveUserWithIDFromTheirTeam returns ErrInvalidID",
			testUserId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 404 when teamService.RemoveUserWithIDFromTheirTeam returns ErrNotFound",
			testUserId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:       "should return 400 when teamService.RemoveUserWithIDFromTheirTeam returns ErrUserNotInTeam",
			testUserId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(services.ErrUserNotInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:       "should return 500 when teamService.RemoveUserWithIDFromTheirTeam returns unknown error",
			testUserId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:       "should return 200 when user id is provided",
			testUserId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:       "should return 200 when user id is me",
			testUserId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().RemoveUserWithIDFromTheirTeam(setup.testCtx, testUserId.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, nil)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.testUserId})

			setup.router.RemoveFromTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
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
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			userId:   "me",
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
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
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 404 when user service returns StatusNotFound",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:     "should return 500 when user service returns unknown error",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
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
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200 when user id is specified",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200 when invalidating service token fails",
			userId:   testUserId.Hex(),
			password: "test",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(common.ErrInvalidToken).Times(1)
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

func TestApiV2Router_GetPasswordResetEmail(t *testing.T) {
	tests := []struct {
		name        string
		userId      string
		prep        func(*usersTestSetup)
		wantResCode int
	}{
		{
			name:   "should return 401 when user id is me and authorizer returns ErrInvalidToken",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when user id is me and authorizer returns ErrInvalidTokenType",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when user id is me and authorizer returns ErrInvalidID",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when user id is me and authorizer returns ErrNotFound",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
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
		// TODO: uncomment tests when password reset is integrated with email service v2
		{
			name:   "should return 500 when user id is me and email service returns error",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockEService.EXPECT().SendPasswordResetEmail(setup.testCtx, *setup.testUser, gomock.Any()).
					Return(errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 when user id is me",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockEService.EXPECT().SendPasswordResetEmail(setup.testCtx, *setup.testUser, gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:   "should return 200 when user id is specified",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(setup.testUser, nil).Times(1)
				setup.mockEService.EXPECT().SendPasswordResetEmail(setup.testCtx, *setup.testUser, gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
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

			setup.router.GetPasswordResetEmail(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestApiV2Router_SetRole(t *testing.T) {
	tests := []struct {
		name        string
		role        string
		prep        func(*usersTestSetup)
		wantResCode int
	}{
		{
			name:        "should return 400 when role is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when provided role is invalid",
			role:        "test",
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when user service returns ErrInvalidID",
			role: "attendee",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 404 when user service returns ErrNotFound",
			role: "attendee",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name: "should return 500 when user service returns unknown error",
			role: "attendee",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 2xx when correct role is provided",
			role: "attendee",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPut, map[string]string{
				"role": tt.role,
			})
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": testUserId.Hex()})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.SetRole(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestApiV2Router_VerifyEmail(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		wantResCode int
	}{
		{
			name: "should return 400 when user service returns ErrInvalidID",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), services.UserUpdateParams{
					entities.UserRole: role.Applicant,
				}).Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 404 when user service returns ErrNotFound",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), services.UserUpdateParams{
					entities.UserRole: role.Applicant,
				}).Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name: "should return 500 when user service returns unknown error",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), services.UserUpdateParams{
					entities.UserRole: role.Applicant,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when user's role gets updated",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), services.UserUpdateParams{
					entities.UserRole: role.Applicant,
				}).Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).Return(nil).
					Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name: "should return 200 when user's role gets updated but invalidating the email token fails",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), services.UserUpdateParams{
					entities.UserRole: role.Applicant,
				}).Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPut, nil)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": testUserId.Hex()})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.VerifyEmail(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestApiV2Router_ResendEmailVerification(t *testing.T) {
	tests := []struct {
		name        string
		userId      string
		prep        func(*usersTestSetup)
		wantResCode int
	}{
		{
			name:   "should return 401 when user id is me authorizer returns ErrInvalidToken",
			userId: "me",
			prep: func(setup *usersTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, common.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:   "should return 400 when user id is provided and user service returns ErrInvalidID",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when user id is provided and user service returns ErrNotFound",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:   "should return 500 when user id is provided and user service returns unknown error",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 500 when email service returns error",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{ID: testUserId}, gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 when email verification is sent",
			userId: testUserId.Hex(),
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{ID: testUserId}, gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
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

			setup.router.ResendEmailVerification(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func BenchmarkApiV2Router_GetUser(b *testing.B) {
	b.StopTimer()

	setup := setupUserBenchmark(b)
	defer setup.cleanup()
	defer setup.ctrl.Finish()

	_, err := setup.uRepo.InsertOne(context.Background(), setup.testUser)
	if err != nil {
		panic(err)
	}
	testToken, _ := setup.authorizer.CreateUserToken(testUserId, testAuthTokenLifetime+setup.timeProvider.Now().Unix())

	testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
	setup.testCtx.Request.Header.Set(authTokenHeader, testToken)
	testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": "me"})

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		setup.router.GetUser(setup.testCtx)
	}
}
