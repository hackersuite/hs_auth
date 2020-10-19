package frontend

import (
	"errors"
	"fmt"
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config/role"
	_ "github.com/unicsmcr/hs_auth/config/role"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	rcommon "github.com/unicsmcr/hs_auth/routers/common"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var testUserId = primitive.NewObjectID()
var emailVerificationURIs = rcommon.MakeEmailVerificationURIs(entities.User{ID: testUserId})
var passwordResetURIs = rcommon.MakePasswordResetURIs(entities.User{ID: testUserId})

type testSetup struct {
	mockUService     *mock_services.MockUserService
	mockEService     *mock_services.MockEmailService
	mockEServiceV2   *mock_services.MockEmailServiceV2
	mockTService     *mock_services.MockTeamService
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	env              *environment.Env
	router           frontendRouter
	testUser         *entities.User
	w                *httptest.ResponseRecorder
	testCtx          *gin.Context
	testServer       *gin.Engine
	claims           *auth.Claims
	emailToken       string
	cfg              *config.AppConfig
	ctrl             *gomock.Controller
}

func setupTest(t *testing.T, envVars map[string]string, authLevel common.AuthLevel) *testSetup {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockEService := mock_services.NewMockEmailService(ctrl)
	mockEServiceV2 := mock_services.NewMockEmailServiceV2(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	restore := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restore()

	cfg := &config.AppConfig{
		BaseAuthLevel: 0,
		Auth: config.AuthConfig{
			UserTokenLifetime: 1000,
		},
	}

	router := frontendRouter{
		logger:         zap.NewNop(),
		cfg:            cfg,
		env:            env,
		userService:    mockUService,
		teamService:    mockTService,
		emailService:   mockEService,
		emailServiceV2: mockEServiceV2,
		authorizer:     mockAuthorizer,
		timeProvider:   mockTimeProvider,
	}

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
	testServer.LoadHTMLGlob("../../templates/*/*.gohtml")

	return &testSetup{
		mockUService:     mockUService,
		mockEService:     mockEService,
		mockEServiceV2:   mockEServiceV2,
		mockTService:     mockTService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		env:              env,
		router:           router,
		testUser:         &testUser,
		w:                w,
		testCtx:          testCtx,
		testServer:       testServer,
		claims:           claims,
		ctrl:             ctrl,
		cfg:              cfg,
	}
}

func Test_LoginPage__should_set_returnto_cookie_correctly(t *testing.T) {
	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()

	mockRenderPageCall(setup)

	testReq := httptest.NewRequest(http.MethodGet, "/?returnto=testurl", nil)

	setup.testCtx.Request = testReq
	setup.router.LoginPage(setup.testCtx)

	assert.True(t, strings.Contains(setup.w.HeaderMap["Set-Cookie"][0], returnToCookie+"=testurl"))
}

func Test_Login(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		email       string
		password    string
		wantResCode int
	}{
		{
			name: "should return 400 when email not specified",
			prep: func(setup *testSetup) {
				mockRenderPageCall(setup)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when password not specified",
			prep: func(setup *testSetup) {
				mockRenderPageCall(setup)
			},
			email:       "test@email.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 404 when GetUserWithEmailAndPwd returns ErrNotFound",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				mockRenderPageCall(setup)
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:     "should return 500 when GetUserWithEmailAndPwd returns unknown error",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				mockRenderPageCall(setup)
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 500 when authorizer returns an error",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				mockRenderPageCall(setup)
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1000, 0)).Times(1)
				setup.mockAuthorizer.EXPECT().CreateUserToken(testUserId, setup.cfg.Auth.UserTokenLifetime+1000).
					Return("", errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when user's email is not verified",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(&entities.User{ID: testUserId, Role: role.Unverified}, nil).Times(1)
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1000, 0)).Times(1)
				setup.mockAuthorizer.EXPECT().CreateUserToken(testUserId, setup.cfg.Auth.UserTokenLifetime+1000).
					Return("authToken", nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(&entities.User{ID: testUserId, Role: role.Unverified}, nil).Times(1)
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1000, 0)).Times(1)
				setup.mockAuthorizer.EXPECT().CreateUserToken(testUserId, setup.cfg.Auth.UserTokenLifetime+1000).
					Return("authToken", nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"email":    tt.email,
				"password": tt.password,
			})
			setup.router.Login(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_Register(t *testing.T) {
	tests := []struct {
		name            string
		prep            func(*testSetup)
		userName        string
		email           string
		password        string
		passwordConfirm string
		wantResCode     int
	}{
		{
			name:            "should return 400 when email not specified",
			password:        "testtest",
			userName:        "bob",
			passwordConfirm: "testtest",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when name not specified",
			password:        "testtest",
			passwordConfirm: "testtest",
			email:           "bob@test.com",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when password not specified",
			userName:        "bob",
			passwordConfirm: "testtest",
			email:           "bob@test.com",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:        "should return 400 when password is too short",
			userName:    "bob",
			password:    "test",
			email:       "bob@test.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when password is too long",
			userName: "bob",
			password: "testtesttesttesttesttesttesttesttesttest" +
				"testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttests",
			email:       "bob@test.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:            "should return 400 when password does not match passwordConfirm",
			userName:        "bob",
			passwordConfirm: "testtest",
			password:        "testtest2",
			email:           "bob@test.com",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when CreateUser returns ErrEmailTaken",
			userName:        "bob",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest", setup.cfg.Auth.DefaultRole).
					Return(nil, services.ErrEmailTaken).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:            "should return 500 when CreateUser returns unknown error",
			userName:        "bob",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest", gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:            "should return 200 even if SendEmailVerificationEmail returns error",
			userName:        "bob",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest", gomock.Any()).
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEServiceV2.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{ID: testUserId}, emailVerificationURIs).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"name":            tt.userName,
				"email":           tt.email,
				"password":        tt.password,
				"passwordConfirm": tt.passwordConfirm,
			})
			setup.router.Register(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_ForgotPassword(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		email       string
		wantResCode int
	}{
		{
			name:        "should return 400 when email not specified",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:  "should return 200 when GetUserWithEmail returns ErrNotFound",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(setup.testCtx, "bob@test.com").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:  "should return 500 when GetUserWithEmail returns unknown error",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(setup.testCtx, "bob@test.com").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 500 when SendPasswordResetEmail returns unknown error",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(setup.testCtx, "bob@test.com").
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEServiceV2.EXPECT().SendPasswordResetEmail(setup.testCtx, entities.User{ID: testUserId}, passwordResetURIs).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 200",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(setup.testCtx, "bob@test.com").
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEServiceV2.EXPECT().SendPasswordResetEmail(setup.testCtx, entities.User{ID: testUserId}, passwordResetURIs).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"email": tt.email,
			})
			setup.router.ForgotPassword(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_ResetPasswordPage(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		jwt         string
		wantResCode int
	}{
		{
			name:        "should return 200",
			jwt:         testAuthToken,
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.testCtx.Request, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("/test?token=%s", tt.jwt), nil)
			setup.router.ResetPasswordPage(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_ResetPassword(t *testing.T) {
	tests := []struct {
		name            string
		prep            func(*testSetup)
		password        string
		passwordConfirm string
		jwt             string
		userId          string
		wantResCode     int
	}{
		{
			name:            "should return 400 when password not specified",
			passwordConfirm: "testtest",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when password does not match passwordConfirm",
			passwordConfirm: "testtest",
			password:        "testtest2",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when user service returns ErrInvalidID",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:            "should return 404 when user service returns ErrNotFound",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:            "should return 500 when user service returns unknown error",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:            "should return 500 when user service returns unknown error",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:            "should return 200 when authorizer fails to invalidate token",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, gomock.Any()).
					Return(authCommon.ErrInvalidTokenType).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:            "should return 200",
			passwordConfirm: "testtest",
			password:        "testtest",
			jwt:             testAuthToken,
			userId:          testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, gomock.Any()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"password":        tt.password,
				"passwordConfirm": tt.passwordConfirm,
				"userId":          tt.userId,
			})
			setup.router.ResetPassword(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_VerifyEmail(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		jwt         string
		userId      string
		wantResCode int
	}{
		{
			name:   "should return 400 when user service returns ErrInvalidID",
			userId: testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 404 when user service returns ErrNotFound",
			userId: testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name:   "should return 500 when user service returns unknown error",
			userId: testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 400 when user's email is already verified",
			userId: testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{Role: role.Applicant}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when updating user fails",
			userId: testUserId.Hex(),
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId, Role: role.Unverified}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200 when invalidating service token fails",
			userId: testUserId.Hex(),
			jwt:    testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId, Role: role.Unverified}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:   "should return 200",
			userId: testUserId.Hex(),
			jwt:    testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId, Role: role.Unverified}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(setup.testCtx, testUserId.Hex(), gomock.Any()).
					Return(nil).Times(1)
				setup.mockAuthorizer.EXPECT().InvalidateServiceToken(setup.testCtx, testAuthToken).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, common.Unverified)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/test?token=%s&userId=%s", tt.jwt, tt.userId), nil)
			setup.testCtx.Request = req

			setup.router.VerifyEmail(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_Logout__should_clear_the_auth_cookie(t *testing.T) {
	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()

	mockRenderPageCall(setup)

	testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
	setup.router.Logout(setup.testCtx)

	assert.True(t, strings.Contains(setup.w.HeaderMap["Set-Cookie"][0], authCookieName+"="))
}

func Test_CreateTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		teamName    string
		jwt         string
		wantResCode int
	}{
		{
			name:        "should return 400 when team name is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when CreateTeamForUserWithJWT returns unknown error",
			teamName: "testteam",
			jwt:      "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", "test").
					Return(nil, errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200",
			teamName: "testteam",
			jwt:      "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().CreateTeamForUserWithJWT(gomock.Any(), "testteam", "test").
					Return(&entities.Team{Name: "testteam"}, nil)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), gomock.Any()).
				Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"name": tt.teamName,
			})
			setup.testCtx.Request.AddCookie(&http.Cookie{
				Name:  authCookieName,
				Value: tt.jwt,
			})

			setup.router.CreateTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_JoinTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		teamID      string
		jwt         string
		wantResCode int
	}{
		{
			name:        "should return 400 when team id is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when AddUserWithJWTToTeamWithID returns ErrNotFound",
			teamID: "testteam",
			jwt:    "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), "test", "testteam").
					Return(services.ErrNotFound)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when AddUserWithJWTToTeamWithID returns ErrUserInTeam",
			teamID: "testteam",
			jwt:    "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), "test", "testteam").
					Return(services.ErrUserInTeam)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when AddUserWithJWTToTeamWithID returns unknown error",
			teamID: "testteam",
			jwt:    "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), "test", "testteam").
					Return(errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:   "should return 200",
			teamID: "testteam",
			jwt:    "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().AddUserWithJWTToTeamWithID(gomock.Any(), "test", "testteam").
					Return(nil)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), gomock.Any()).
				Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"id": tt.teamID,
			})
			setup.testCtx.Request.AddCookie(&http.Cookie{
				Name:  authCookieName,
				Value: tt.jwt,
			})

			setup.router.JoinTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_LeaveTeam(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		jwt         string
		wantResCode int
	}{
		{
			name: "should return 400 when RemoveUserWithJWTFromTheirTeam returns ErrNotFound",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "test").
					Return(services.ErrNotFound)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when RemoveUserWithJWTFromTheirTeam returns ErrUserNotInTeam",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "test").
					Return(services.ErrUserNotInTeam)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when RemoveUserWithJWTFromTheirTeam returns unknown error",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "test").
					Return(errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "test").
					Return(nil)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), gomock.Any()).
				Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{})
			setup.testCtx.Request.AddCookie(&http.Cookie{
				Name:  authCookieName,
				Value: tt.jwt,
			})

			setup.router.LeaveTeam(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_UpdateUser(t *testing.T) {
	tests := []struct {
		name           string
		prep           func(*testSetup)
		userID         string
		paramsToUpdate string
		wantResCode    int
	}{
		{
			name:        "should return 400 when no userID is provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:           "should return 400 when paramsToUpdate is not map[entities.UserField]string",
			wantResCode:    http.StatusBadRequest,
			userID:         "test id",
			paramsToUpdate: "{\"auth_level\":3}",
		},
		{
			name:           "should return 400 when paramsToUpdate cannot be built to services.UserUpdateParams",
			wantResCode:    http.StatusBadRequest,
			userID:         "test id",
			paramsToUpdate: "{\"auth_level\":\"not a number\"}",
		},
		{
			name:           "should return 400 when paramsToUpdate include password",
			wantResCode:    http.StatusBadRequest,
			userID:         "test id",
			paramsToUpdate: "{\"password\":\"not a number\"}",
		},
		{
			name:           "should return 400 when paramsToUpdate include _id",
			wantResCode:    http.StatusBadRequest,
			userID:         "test id",
			paramsToUpdate: "{\"_id\":\"not a number\"}",
		},
		{
			name:           "should return 400 when user service returns ErrInvalidID",
			userID:         "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(services.ErrInvalidID)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:           "should return 400 when user service returns ErrInvalidID",
			userID:         "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(services.ErrInvalidID)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:           "should return 500 when user service returns unknown error",
			userID:         "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:           "should return 200 when updating user succeeds",
			userID:         "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", services.UserUpdateParams{
					entities.UserName: "Rob the Tester",
				}).
					Return(nil)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), gomock.Any()).
				Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"set": tt.paramsToUpdate,
			})
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.userID})
			setup.testCtx.Request.AddCookie(&http.Cookie{
				Name:  authCookieName,
				Value: "test",
			})

			setup.router.UpdateUser(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_VerifyEmailResend(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		jwt         string
		wantResCode int
	}{
		{
			name: "should return 401 when authorizer returns ErrInvalidToken",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, authCommon.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 500 when authorizer returns unknown error",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 404 when user service returns ErrNotFound",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusNotFound,
		},
		{
			name: "should return 500 when user service returns unknown error",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 500 when email service returns error",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEServiceV2.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{ID: testUserId}, emailVerificationURIs).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200",
			jwt:  testAuthToken,
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{ID: testUserId}, nil).Times(1)
				setup.mockEServiceV2.EXPECT().SendEmailVerificationEmail(setup.testCtx, entities.User{ID: testUserId}, emailVerificationURIs).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)
			defer setup.ctrl.Finish()

			mockRenderPageCall(setup)

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{})
			setup.testCtx.Request.AddCookie(&http.Cookie{
				Name:  authCookieName,
				Value: tt.jwt,
			})

			setup.router.VerifyEmailResend(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func TestFrontendRouter_ProfilePage(t *testing.T) {
	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()

	attachAuthCookie(setup.testCtx)
	mockRenderPageCall(setup)

	setup.router.ProfilePage(setup.testCtx)

	assert.Equal(t, http.StatusOK, setup.w.Code)
}

func mockRenderPageCall(setup *testSetup) {
	setup.mockAuthorizer.EXPECT().GetAuthorizedResources(setup.testCtx, gomock.Any(), gomock.Any()).
		Return(nil, nil).Times(1)
}

func attachAuthCookie(ctx *gin.Context) {
	if ctx.Request == nil {
		ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	}
	ctx.Request.AddCookie(&http.Cookie{
		Name:   authCookieName,
		Value:  testAuthToken,
		MaxAge: 1000,
	})
}
