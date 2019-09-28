package frontend

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	env          *environment.Env
	router       Router
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

	restore := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restore()

	router := NewRouter(zap.NewNop(), &config.AppConfig{
		BaseAuthLevel: 0,
	}, env, mockUService, mockEService)

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
	testCtx.Set(auth.AuthTokenKeyInCtx, claims)
	testServer.LoadHTMLGlob("../../templates/*/*.gohtml")

	return &testSetup{
		mockUService: mockUService,
		mockEService: mockEService,
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
