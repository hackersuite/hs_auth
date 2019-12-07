package v1

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const (
	baseTestAuthLevel     = common.Applicant
	testAuthTokenLifetime = 10000000
)

type usersTestSetup struct {
	mockUService *mock_services.MockUserService
	mockEService *mock_services.MockEmailService
	mockTService *mock_services.MockTeamService
	env          *environment.Env
	router       APIV1Router
	testServer   *gin.Engine
	w            *httptest.ResponseRecorder
	testCtx      *gin.Context
	testUser     *entities.User
	claims       *auth.Claims
	jwt          string
}

func setupUsersTest(t *testing.T, envVars map[string]string) *usersTestSetup {
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

	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		Name:      "Bob the Tester",
		Email:     "test@email.com",
		AuthLevel: baseTestAuthLevel,
		Team:      primitive.NewObjectID(),
		Password:  "password123",
	}

	jwt, _ := auth.NewJWT(testUser, time.Now().Unix(), testAuthTokenLifetime, auth.Auth, []byte(env.Get(environment.JWTSecret)))
	claims := auth.GetJWTClaims(jwt, []byte(env.Get(environment.JWTSecret)))

	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)

	return &usersTestSetup{
		mockUService: mockUService,
		mockEService: mockEService,
		mockTService: mockTService,
		testUser:     &testUser,
		env:          env,
		router:       router,
		testServer:   testServer,
		w:            w,
		testCtx:      testCtx,
		claims:       claims,
		jwt:          jwt,
	}
}

func Test_GetUsers(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		wantResCode int
		wantRes     *getUsersRes
	}{
		{
			name: "should return 500 when fetching users fails",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and expected users",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUsers(gomock.Any()).
					Return([]entities.User{
						{Name: "Bob the Tester"},
						{Name: "Rob the Tester"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getUsersRes{
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
			setup := setupUsersTest(t, nil)
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

func Test_Login(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		prep        func(*usersTestSetup)
		wantResCode int
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
			name:        "should return 500 when generating JWT fails due to undefined JWT secret",
			email:       "test@email.com",
			password:    "password123",
			wantResCode: http.StatusInternalServerError,
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
					Return(setup.testUser, nil).Times(1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t, map[string]string{
				environment.JWTSecret: tt.jwtSecret,
			})
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
		})
	}
}

func Test_Login__should_return_expected_result(t *testing.T) {
	setup := setupUsersTest(t, map[string]string{
		environment.JWTSecret: "verysecret",
	})
	setup.mockUService.EXPECT().GetUserWithEmailAndPwd(gomock.Any(), "test@email.com", "password123").
		Return(setup.testUser, nil).Times(1)

	testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
		http.MethodPost,
		map[string]string{
			"email":    "test@email.com",
			"password": "password123",
		},
	)

	setup.router.Login(setup.testCtx)

	assert.Equal(t, http.StatusOK, setup.w.Code)

	var actualRes loginRes
	err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
	assert.NoError(t, err)

	setup.testUser.Password = ""
	assert.Equal(t, loginRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Token: setup.jwt,
		User:  *setup.testUser,
	}, actualRes)
}

func Test_GetMe(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		jwt         string
		wantResCode int
		wantRes     *getMeRes
	}{
		{
			name: "should return 401 when user service returns ErrInvalidToken",
			jwt:  "invalid token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "invalid token").
					Return(nil, services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when user service return ErrNotFound",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when user service return unknown error",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return expected user",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetUserWithJWT(gomock.Any(), "").
					Return(&entities.User{
						Name: "Bob the Tester",
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getMeRes{
				Response: models.Response{Status: http.StatusOK},
				User:     entities.User{Name: "Bob the Tester"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set(authHeaderName, tt.jwt)
			setup.testCtx.Request = req

			setup.router.GetMe(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getMeRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_PutMe(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		jwt         string
		testName    string
		testTeam    string
		wantResCode int
		wantRes     *models.Response
	}{
		{
			name:        "should return 400 when neither name nor team provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when team service returns ErrInvalidID",
			testTeam: "some team",
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "some team").
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when team service returns ErrNotFound",
			testTeam: "some team",
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "some team").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when team service returns unknown error",
			testTeam: "some team",
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "some team").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 401 when user service returns ErrInvalidToken",
			jwt:      "token",
			testName: "Rob the Tester",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "token", services.UserUpdateParams{
					entities.UserName: "Rob the Tester",
				}).Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:     "should return 500 when user service returns unknown error",
			jwt:      "token",
			testName: "Rob the Tester",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "token", services.UserUpdateParams{
					entities.UserName: "Rob the Tester",
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when user service returns nil",
			jwt:      "token",
			testName: "Rob the Tester",
			testTeam: "some team",
			prep: func(setup *usersTestSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "some team").
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "token", services.UserUpdateParams{
					entities.UserName: "Rob the Tester",
					entities.UserTeam: "some team",
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &models.Response{
				Status: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
				http.MethodPut,
				map[string]string{
					"name": tt.testName,
					"team": tt.testTeam,
				},
			)
			setup.testCtx.Request.Header.Set(authHeaderName, tt.jwt)

			setup.router.PutMe(setup.testCtx)

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

func Test_Register(t *testing.T) {
	tests := []struct {
		name         string
		prep         func(*usersTestSetup)
		testName     string
		testEmail    string
		testPassword string
		wantResCode  int
		wantRes      *registerRes
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
			name:         "should return 500 and delete created user when email service returns error",
			testName:     "Bob the Tester",
			testEmail:    "test@email.com",
			testPassword: "password123",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().CreateUser(gomock.Any(), "Bob the Tester", "test@email.com", "password123").
					Return(&entities.User{Name: "Bob the Tester"}, nil).Times(1)

				setup.mockEService.EXPECT().SendEmailVerificationEmail(entities.User{Name: "Bob the Tester"}).
					Return(errors.New("service err")).Times(1)

				setup.mockUService.EXPECT().DeleteUserWithEmail(gomock.Any(), "test@email.com").
					Return(nil).Times(1)
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

				setup.mockEService.EXPECT().SendEmailVerificationEmail(entities.User{Name: "Bob the Tester"}).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &registerRes{
				Response: models.Response{Status: http.StatusOK},
				User: entities.User{
					Name: "Bob the Tester",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t, nil)
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

			if tt.wantRes != nil {
				var actualRes registerRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func Test_VerifyEmail(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		jwt         string
		wantResCode int
		wantRes     *models.Response
	}{
		{
			name: "should return 401 when user service returns ErrInvalidToken",
			jwt:  "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test token", services.UserUpdateParams{
					entities.UserEmailVerified: true,
				}).Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 500 when user service returns an unknown error",
			jwt:  "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test token", services.UserUpdateParams{
					entities.UserEmailVerified: true,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and expected result",
			jwt:  "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().UpdateUserWithJWT(gomock.Any(), "test token", services.UserUpdateParams{
					entities.UserEmailVerified: true,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &models.Response{
				Status: http.StatusOK,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set(authHeaderName, tt.jwt)
			setup.testCtx.Request = req

			setup.router.VerifyEmail(setup.testCtx)

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

func Test_GetPasswordResetEmail(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*usersTestSetup)
		email       string
		wantResCode int
		wantRes     *models.Response
	}{
		{
			name:        "should return 400 when email is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:  "should return 500 when email service returns error",
			email: "test@email.com",
			prep: func(setup *usersTestSetup) {
				setup.mockEService.EXPECT().SendPasswordResetEmailForUserWithEmail(gomock.Any(), "test@email.com").
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 200 and expected result",
			email: "test@email.com",
			prep: func(setup *usersTestSetup) {
				setup.mockEService.EXPECT().SendPasswordResetEmailForUserWithEmail(gomock.Any(), "test@email.com").
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
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/test?email=%s", tt.email), nil)
			setup.testCtx.Request = req

			setup.router.GetPasswordResetEmail(setup.testCtx)

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

func Test_ResetPassword(t *testing.T) {
	tests := []struct {
		name         string
		prep         func(*usersTestSetup)
		testEmail    string
		testPassword string
		jwt          string
		wantResCode  int
		wantRes      *models.Response
	}{
		{
			name:         "should return 400 when email is not provided",
			testPassword: "password123",
			wantResCode:  http.StatusBadRequest,
		},
		{
			name:        "should return 400 when password is not provided",
			testEmail:   "test@email.com",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:         "should return 401 when user service returns ErrInvalidToken",
			testEmail:    "test@email.com",
			testPassword: "password123",
			jwt:          "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().ResetPasswordForUserWithJWTAndEmail(gomock.Any(), "test token", "test@email.com", "password123").
					Return(services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:         "should return 500 when user service returns an unknown error",
			testEmail:    "test@email.com",
			testPassword: "password123",
			jwt:          "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().ResetPasswordForUserWithJWTAndEmail(gomock.Any(), "test token", "test@email.com", "password123").
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:         "should return 200 and the expected result",
			testEmail:    "test@email.com",
			testPassword: "password123",
			jwt:          "test token",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().ResetPasswordForUserWithJWTAndEmail(gomock.Any(), "test token", "test@email.com", "password123").
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
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			data := url.Values{}
			data.Add("password", tt.testPassword)

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/test?email=%s", tt.testEmail), bytes.NewBufferString(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			req.Header.Set(authHeaderName, tt.jwt)
			setup.testCtx.Request = req

			setup.router.ResetPassword(setup.testCtx)

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

func Test_GetTeammates(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(setup *usersTestSetup)
		wantResCode int
		jwt         string
		wantRes     *getTeammatesRes
	}{
		{
			name: "should pass correct jwt to team service",
			jwt:  "testjwt",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), "testjwt").
					Return([]entities.User{}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name: "should return 401 when team service returns ErrInvalidToken",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return(nil, services.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
		},
		{
			name: "should return 400 when team service returns ErrInvalidID",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when team service returns ErrNotFound",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 400 when team service returns ErrUserNotInTeam",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return(nil, services.ErrUserNotInTeam).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name: "should return 500 when team service returns unknown error",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name: "should return 200 and correct teammates",
			prep: func(setup *usersTestSetup) {
				setup.mockUService.EXPECT().GetTeammatesForUserWithJWT(gomock.Any(), gomock.Any()).
					Return([]entities.User{
						{Name: "Bob the Tester"},
						{Name: "Rob the Tester"},
					}, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &getTeammatesRes{
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
			setup := setupUsersTest(t, nil)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodGet, nil)
			setup.testCtx.Request.Header.Set(authHeaderName, tt.jwt)

			setup.router.GetTeammates(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes getTeammatesRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}
