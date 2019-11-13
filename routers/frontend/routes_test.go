package frontend

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

type testSetup struct {
	mockUService *mock_services.MockUserService
	mockEService *mock_services.MockEmailService
	mockTService *mock_services.MockTeamService
	env          *environment.Env
	router       Router
	testUser     *entities.User
	w            *httptest.ResponseRecorder
	testCtx      *gin.Context
	testServer   *gin.Engine
	claims       *auth.Claims
	authToken    string
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

	router := NewRouter(zap.NewNop(), &config.AppConfig{
		BaseAuthLevel: 0,
	}, env, mockUService, mockTService, mockEService)

	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		Name:      "John Doe",
		Email:     "john@doe.com",
		AuthLevel: authLevel,
		Team:      primitive.NewObjectID(),
	}

	token, _ := auth.NewJWT(testUser, time.Now().Unix(), 10000000, auth.Auth, []byte(env.Get(environment.JWTSecret)))

	claims := auth.GetJWTClaims(token, []byte(env.Get(environment.JWTSecret)))
	if claims == nil {
		claims = &auth.Claims{
			StandardClaims: jwt.StandardClaims{
				Id: testUser.ID.Hex(),
			},
			AuthLevel: testUser.AuthLevel,
		}
	}

	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	testCtx.Set(auth.AuthTokenKeyInCtx, claims)
	testCtx.SetCookie(auth.AuthHeaderName, token, 10000000000000, "/", "127.0.0.1", false, true)
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
		authToken:    token,
	}
}

func Test_LoginPage__should_set_returnto_cookie_correctly(t *testing.T) {
	setup := setupTest(t, nil, 0)

	testReq := httptest.NewRequest(http.MethodGet, "/?returnto=testurl", nil)

	setup.testCtx.Request = testReq
	setup.router.LoginPage(setup.testCtx)

	assert.True(t, strings.Contains(setup.w.HeaderMap["Set-Cookie"][1], ReturnToCookie+"=testurl"))
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
			name:     "should return 400 when user with email doesn't exist",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "test@email.com").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 500 when query for user with email fails",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "test@email.com").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 400 when password is incorrect",
			email:    "test@email.com",
			password: "testpassword",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "test@email.com").
					Return(&entities.User{
						Password: "invalidpwd",
					}, nil).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, 0)

			if tt.prep != nil {
				tt.prep(setup)
			}

			data := url.Values{}
			data.Add("email", tt.email)
			data.Add("password", tt.password)

			testReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(data.Encode()))
			testReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			setup.testCtx.Request = testReq
			setup.router.Login(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_SetTeamTableNo(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(*testSetup)
		table       string
		wantResCode int
	}{
		{
			name:        "should return 400 when table number not specified",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when table number is not a number",
			table:       "not a number",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:        "should return 400 when table number is not > 0",
			table:       "0",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:  "should return 500 when user service returns error",
			table: "3",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("service err")).Times(2)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 500 when team service returns error",
			table: "3",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).
					Return(setup.testUser, nil).Times(2)
				setup.mockTService.EXPECT().UpdateTeamWithID(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, map[string]string{
				environment.JWTSecret: "testscrt",
			}, 0)

			if tt.prep != nil {
				tt.prep(setup)
			}

			data := url.Values{}
			data.Add("table", tt.table)

			testReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(data.Encode()))
			testReq.AddCookie(&http.Cookie{
				Name:   auth.AuthHeaderName,
				Value:  setup.authToken,
				MaxAge: 100000000000000,
			})

			setup.testUser.Team = primitive.NilObjectID
			setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).Return(setup.testUser, nil).Times(1)
			testReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			setup.testCtx.Request = testReq
			setup.router.SetTeamTableNo(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}

func Test_SetTeamTableNo__should_update_the_correct_team_with_the_correct_table_num(t *testing.T) {
	setup := setupTest(t, map[string]string{
		environment.JWTSecret: "testscrt",
	}, 0)

	data := url.Values{}
	data.Add("table", "3")

	testReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(data.Encode()))
	testReq.AddCookie(&http.Cookie{
		Name:   auth.AuthHeaderName,
		Value:  setup.authToken,
		MaxAge: 100000000000000,
	})

	setup.mockUService.EXPECT().GetUserWithID(gomock.Any(), setup.testUser.ID.Hex()).Return(setup.testUser, nil).Times(2)
	setup.mockTService.EXPECT().UpdateTeamWithID(gomock.Any(), setup.testUser.Team.Hex(), map[string]interface{}{
		"table_no": 3,
	}).Return(nil).Times(1)
	setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), setup.testUser.Team.Hex()).
		Return(&entities.Team{}, nil).Times(1)
	setup.mockUService.EXPECT().GetUsersWithTeam(gomock.Any(), setup.testUser.Team.Hex()).
		Return([]entities.User{}, nil).Times(1)
	testReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	setup.testCtx.Request = testReq
	setup.router.SetTeamTableNo(setup.testCtx)

	assert.Equal(t, http.StatusOK, setup.w.Code)
}
