package frontend

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

type testSetup struct {
	mockUService *mock_services.MockUserService
	mockEService *mock_services.MockEmailService
	mockTService *mock_services.MockTeamService
	env          *environment.Env
	router       frontendRouter
	testUser     *entities.User
	w            *httptest.ResponseRecorder
	testCtx      *gin.Context
	testServer   *gin.Engine
	claims       *auth.Claims
	emailToken   string
}

func setupTest(t *testing.T, envVars map[string]string, authLevel common.AuthLevel) *testSetup {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockEService := mock_services.NewMockEmailService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)

	restore := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restore()

	router := frontendRouter{
		logger: zap.NewNop(),
		cfg: &config.AppConfig{
			BaseAuthLevel: 0,
		},
		env:          env,
		userService:  mockUService,
		teamService:  mockTService,
		emailService: mockEService,
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
		mockUService: mockUService,
		mockEService: mockEService,
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

func Test_LoginPage__should_set_returnto_cookie_correctly(t *testing.T) {
	setup := setupTest(t, nil, 0)

	testReq := httptest.NewRequest(http.MethodGet, "/?returnto=testurl", nil)

	setup.testCtx.Request = testReq
	setup.router.LoginPage(setup.testCtx)

	assert.True(t, strings.Contains(setup.w.HeaderMap["Set-Cookie"][0], ReturnToCookie+"=testurl"))
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
			name:        "should return 400 when email not specified",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when password not specified",
			email:       "test@email.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 401 when GetUserWithEmailAndPwd returns ErrNotFound",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 500 when GetUserWithEmailAndPwd returns unknown error",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when user's email is not verified",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(&entities.User{AuthLevel: common.Unverified}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "testpassword").
					Return(&entities.User{AuthLevel: common.Organiser}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

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

func Test_renderProfilePage(t *testing.T) {
	tests := []struct {
		name            string
		jwt             string
		prep            func(setup *testSetup)
		givenStatusCode int
		givenErr        string
		wantResCode     int
	}{
		{
			name:        "should return 401 when auth cookie is empty",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 500 when getBasicUserInfo returns error",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return correct status code",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)
			},
			givenStatusCode: http.StatusOK,
			wantResCode:     http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, common.Applicant)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
			if tt.jwt != "" {
				setup.testCtx.Request.AddCookie(&http.Cookie{
					Name:  authCookieName,
					Value: tt.jwt,
				})
			}
			setup.router.renderProfilePage(setup.testCtx, tt.givenStatusCode, tt.givenErr)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_getProfilePageData(t *testing.T) {
	userID := primitive.NewObjectID()
	teamID := primitive.NewObjectID()

	tests := []struct {
		name    string
		prep    func(setup *testSetup)
		wantOut profilePageData
		wantErr bool
	}{
		{
			name: "should return error when GetUserWithJWT returns error",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantErr: true,
			wantOut: profilePageData{},
		},
		{
			name: "should return empty team and teammates when user does not have team",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)
			},
			wantOut: profilePageData{
				User:      &entities.User{Name: "Bob the Tester"},
				Team:      nil,
				Teammates: nil,
			},
		},
		{
			name: "should return the user and no team when GetTeamWithID returns error",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{Name: "Bob the Tester", Team: teamID}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), teamID.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantOut: profilePageData{
				User:      &entities.User{Name: "Bob the Tester", Team: teamID},
				Team:      nil,
				Teammates: nil,
			},
		},
		{
			name: "should return the user and their team but no teammates or error when GetTeammatesForUserWithID returns error",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{ID: userID, Name: "Bob the Tester", Team: teamID}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), teamID.Hex()).
					Return(&entities.Team{Name: "Team of Bobs", ID: teamID}, nil).Times(1)
				setup.mockUService.EXPECT().GetTeammatesForUserWithID(gomock.Any(), userID.Hex()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantOut: profilePageData{
				User: &entities.User{ID: userID, Name: "Bob the Tester", Team: teamID},
				Team: &entities.Team{Name: "Team of Bobs", ID: teamID},
			},
		},
		{
			name: "should return the user and an empty AdminData when user is Organiser and GetUsers returns err",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{ID: userID, Name: "Bob the Tester", AuthLevel: common.Organiser}, nil).Times(1)
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantOut: profilePageData{
				User:      &entities.User{ID: userID, Name: "Bob the Tester", AuthLevel: common.Organiser},
				AdminData: adminData{},
			},
		},
		{
			name: "should include all users in AdminData when user is an Organiser",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{ID: userID, Name: "Bob the Tester", AuthLevel: common.Organiser}, nil).Times(1)
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).
					Return([]entities.User{{Name: "Bob the Tester"}, {Name: "Rob the Tester"}}, nil).Times(1)
			},
			wantOut: profilePageData{
				User: &entities.User{ID: userID, Name: "Bob the Tester", AuthLevel: common.Organiser},
				AdminData: adminData{
					Users: []entities.User{{Name: "Bob the Tester"}, {Name: "Rob the Tester"}},
				},
			},
		},
		{
			name: "should return the user, their team and teammates",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{ID: userID, Name: "Bob the Tester", Team: teamID}, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), teamID.Hex()).
					Return(&entities.Team{Name: "Team of Bobs", ID: teamID}, nil).Times(1)
				setup.mockUService.EXPECT().GetTeammatesForUserWithID(gomock.Any(), userID.Hex()).
					Return([]entities.User{{Name: "Rob the Tester"}}, nil).Times(1)
			},
			wantOut: profilePageData{
				User:      &entities.User{ID: userID, Name: "Bob the Tester", Team: teamID},
				Team:      &entities.Team{Name: "Team of Bobs", ID: teamID},
				Teammates: []entities.User{{Name: "Rob the Tester"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, common.Applicant)
			if tt.prep != nil {
				tt.prep(setup)
			}

			uInfo, err := setup.router.getProfilePageData(setup.testCtx, "test")
			assert.Equal(t, tt.wantOut, uInfo)
			assert.Equal(t, tt.wantErr, err != nil)
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest").
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest").
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
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "bob", "bob@test.com", "testtest").
					Return(&entities.User{}, nil).Times(1)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(entities.User{}).
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
			name:  "should return 200 when SendPasswordResetEmailForUserWithEmail returns ErrEmailTaken",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockEService.EXPECT().SendPasswordResetEmailForUserWithEmail(gomock.Any(), "bob@test.com").
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:  "should return 500 when SendPasswordResetEmailForUserWithEmail returns unknown error",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockEService.EXPECT().SendPasswordResetEmailForUserWithEmail(gomock.Any(), "bob@test.com").
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 200",
			email: "bob@test.com",
			prep: func(setup *testSetup) {
				setup.mockEService.EXPECT().SendPasswordResetEmailForUserWithEmail(gomock.Any(), "bob@test.com").
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

func Test_ResetPassword(t *testing.T) {
	tests := []struct {
		name            string
		prep            func(*testSetup)
		userName        string
		email           string
		password        string
		passwordConfirm string
		jwt             string
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
			name:            "should return 400 when password not specified",
			passwordConfirm: "testtest",
			email:           "bob@test.com",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when password does not match passwordConfirm",
			passwordConfirm: "testtest",
			password:        "testtest2",
			email:           "bob@test.com",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 401 when UpdateUserWithJWT returns ErrInvalidToken",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			jwt:             "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test", gomock.Any()).
					Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:            "should return 401 when UpdateUserWithJWT returns ErrNotFound",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			jwt:             "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test", gomock.Any()).
					Return(services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:            "should return 500 when UpdateUserWithJWT returns unknown error",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			jwt:             "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test", gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:            "should return 200",
			passwordConfirm: "testtest",
			password:        "testtest",
			email:           "bob@test.com",
			jwt:             "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test", gomock.Any()).
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

			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodPost, map[string]string{
				"email":           tt.email,
				"password":        tt.password,
				"passwordConfirm": tt.passwordConfirm,
				"token":           tt.jwt,
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
		wantResCode int
	}{
		{
			name:        "should return 401 when jwt is empty",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 401 when GetUserWithJWT returns ErrInvalidToken",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(nil, services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when GetUserWithJWT returns ErrNotFound",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when GetUserWithJWT returns unknown error",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 401 when user's auth level is below Unverified",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(&entities.User{AuthLevel:common.AuthLevel(-111)}, nil).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when user's auth level is above Unverified",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(&entities.User{AuthLevel:common.Unverified + 1}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when UpdateUserWithID returns error",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(&entities.User{AuthLevel:common.Unverified}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), primitive.NilObjectID.Hex(), services.UserUpdateParams{
					entities.UserAuthLevel: common.Applicant,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200",
			jwt:  "test_token",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test_token").
					Return(&entities.User{AuthLevel:common.Unverified}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), primitive.NilObjectID.Hex(), services.UserUpdateParams{
					entities.UserAuthLevel: common.Applicant,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, common.Unverified)

			if tt.prep != nil {
				tt.prep(setup)
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/test?token=%s", tt.jwt), nil)
			setup.testCtx.Request = req

			setup.router.VerifyEmail(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_Logout__should_clear_the_auth_cookie(t *testing.T) {
	setup := setupTest(t, nil, 0)

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
			name: "should return 400 when no userID is provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when paramsToUpdate is not map[entities.UserField]string",
			wantResCode: http.StatusBadRequest,
			userID: "test id",
			paramsToUpdate: "{\"auth_level\":3}",
		},
		{
			name: "should return 400 when paramsToUpdate cannot be built to services.UserUpdateParams",
			wantResCode: http.StatusBadRequest,
			userID: "test id",
			paramsToUpdate: "{\"auth_level\":\"not a number\"}",
		},
		{
			name: "should return 400 when paramsToUpdate include password",
			wantResCode: http.StatusBadRequest,
			userID: "test id",
			paramsToUpdate: "{\"password\":\"not a number\"}",
		},
		{
			name: "should return 400 when paramsToUpdate include _id",
			wantResCode: http.StatusBadRequest,
			userID: "test id",
			paramsToUpdate: "{\"_id\":\"not a number\"}",
		},
		{
			name: "should return 400 when user service returns ErrInvalidID",
			userID: "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(services.ErrInvalidID)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when user service returns ErrInvalidID",
			userID: "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(services.ErrInvalidID)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when user service returns unknown error",
			userID: "test id",
			paramsToUpdate: "{\"name\":\"Rob the Tester\"}",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), "test id", gomock.Any()).
					Return(errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when updating user succeeds",
			userID: "test id",
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
			name: "should return 401 when GetUserWithJWT returns ErrInvalidToken",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(nil, services.ErrInvalidToken)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when GetUserWithJWT returns ErrNotFound",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(nil, services.ErrNotFound)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when GetUserWithJWT returns unknown error",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(nil, errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 500 when SendEmailVerificationEmail returns error",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{}, nil)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(gomock.Any()).
					Return(errors.New("service err"))
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 when SendEmailVerificationEmail returns nil",
			jwt:  "test",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "test").
					Return(&entities.User{}, nil)
				setup.mockEService.EXPECT().SendEmailVerificationEmail(gomock.Any()).
					Return(nil)
			},
			wantResCode: http.StatusOK,
		},
		//{
		//	name: "should return 200",
		//	jwt:  "test",
		//	prep: func(setup *testSetup) {
		//		setup.mockTService.EXPECT().RemoveUserWithJWTFromTheirTeam(gomock.Any(), "test").
		//			Return(nil)
		//	},
		//	wantResCode: http.StatusOK,
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "test",
			}, 0)

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