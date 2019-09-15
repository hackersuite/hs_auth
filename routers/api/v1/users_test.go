package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/unicsmcr/hs_auth/config"

	"github.com/unicsmcr/hs_auth/services"

	"github.com/unicsmcr/hs_auth/utils/auth"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/dgrijalva/jwt-go"

	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/testutils"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/entities"

	"github.com/golang/mock/gomock"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
)

const testPassword = "password123"
const testUserID = "5d7a9386e48fa16556c56411"
const testAuthLevel = 3
const testEmailVerified = true

func setupTest(t *testing.T, envVars map[string]string) (*mock_services.MockUserService, *mock_services.MockEmailService, *httptest.ResponseRecorder, *gin.Context, *gin.Engine, APIV1Router, entities.User, string) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockESercive := mock_services.NewMockEmailService(ctrl)
	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	restoreVars := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restoreVars()
	router := NewAPIV1Router(zap.NewNop(), &config.AppConfig{
		BaseAuthLevel: 0,
	}, mockUService, mockESercive, nil, env)
	password, err := auth.GetHashForPassword(testPassword)
	assert.NoError(t, err)
	userID, err := primitive.ObjectIDFromHex(testUserID)
	assert.NoError(t, err)
	testUser := entities.User{
		AuthLevel:     testAuthLevel,
		Password:      password,
		ID:            userID,
		EmailVerified: testEmailVerified,
	}
	var token string
	if env.Get(environment.JWTSecret) != "" {
		var err error
		token, err = auth.NewJWT(testUser, 100, 0, auth.Email, []byte(env.Get(environment.JWTSecret)))
		assert.NoError(t, err)
		testCtx.Set(authClaimsKeyInCtx, &auth.Claims{
			AuthLevel: testAuthLevel,
			TokenType: auth.Auth,
			StandardClaims: jwt.StandardClaims{
				Id: userID.Hex(),
			},
		})
	}

	return mockUService, mockESercive, w, testCtx, testServer, router, testUser, token
}

func setupUserTest(t *testing.T, envVars map[string]string, authLevel common.AuthLevel) *testSetup {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)
	mockEService := mock_services.NewMockEmailService(ctrl)

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

	var emailToken string
	if env.Get(environment.JWTSecret) != "" {
		var err error
		emailToken, err = auth.NewJWT(testUser, 100, 0, auth.Email, []byte(env.Get(environment.JWTSecret)))
		assert.NoError(t, err)
	}

	return &testSetup{
		mockUService: mockUService,
		mockTService: mockTService,
		mockEService: mockEService,
		env:          env,
		router:       router,
		testUser:     &testUser,
		w:            w,
		testCtx:      testCtx,
		testServer:   testServer,
		claims:       claims,
		emailToken:   emailToken,
	}
}

func Test_GetUsers__should_call_GetUsers_on_UserService(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	expectedRes := getUsersRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: []entities.User{entities.User{Name: "Bob Tester"}},
	}
	mockUService.EXPECT().GetUsers(gomock.Any()).Return(expectedRes.Users, nil).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set(authHeaderName, token)
	testCtx.Request = req
	router.GetUsers(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes getUsersRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedRes, actualRes)
}

func Test_GetUsers__should_return_error_when_UserService_returns_error(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	expectedAPIError := models.NewAPIError(http.StatusInternalServerError, "service err")

	mockUService.EXPECT().GetUsers(gomock.Any()).Return(nil, errors.New(expectedAPIError.Err)).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set(authHeaderName, token)
	testCtx.Request = req
	router.GetUsers(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes models.APIError
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, expectedAPIError.Status, w.Code)
	assert.Equal(t, expectedAPIError, actualRes)
}

func Test_Login__should_call_UserService_and_return_correct_token_and_user(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().
		GetUserWithEmail(gomock.Any(), "john@doe.com").
		Return(&testUser, nil).Times(1)

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes loginRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, actualRes.Status)
	assert.Zero(t, actualRes.Err)

	var claims auth.Claims
	_, err = jwt.ParseWithClaims(actualRes.Token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte("testsecret"), nil
	})
	assert.NoError(t, err)
	assert.Equal(t, testUser.ID.Hex(), claims.Id)
	assert.Equal(t, testUser.AuthLevel, claims.AuthLevel)

	assert.NotNil(t, auth.GetJWTClaims(actualRes.Token, []byte("testsecret")))
	testUser.Password = actualRes.User.Password
	assert.Equal(t, testUser, actualRes.User)
}

func Test_Login__should_return_500_when_user_service_returns_error(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().
		GetUserWithEmail(gomock.Any(), "john@doe.com").
		Return(nil, errors.New("service err")).Times(1)

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Login__should_return_StatusBadRequest_when_no_email_is_provided(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})
	data := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes loginRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, actualRes.Status)
	assert.Equal(t, "email must be provided", actualRes.Err)
}

func Test_Login__should_return_StatusBadRequest_when_no_password_is_provided(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})
	data := url.Values{}
	data.Add("email", "john@doe.com")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes loginRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, actualRes.Status)
	assert.Equal(t, "password must be provided", actualRes.Err)
}

func Test_Login__should_return_StatusUnauthorized_when_invalid_credentials_are_provided(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})
	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").
		Return(nil, services.ErrNotFound).Times(1)

	router.Login(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes loginRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, actualRes.Status)
	assert.Equal(t, "user not found", actualRes.Err)
}

func Test_Verify__should_return_StatusOK_for_valid_token(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set(authHeaderName, token)
	testCtx.Request = req

	router.Verify(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_GetMe__should_return_400_when_auth_claims_are_nil(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	testCtx.Set(authClaimsKeyInCtx, nil)
	router.GetMe(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_GetMe__should_return_400_if_user_in_claims_doesnt_exist(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(nil, services.ErrNotFound).Times(1)
	router.GetMe(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_GetMe__should_return_500_if_user_service_returns_err(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(nil, errors.New("service err")).Times(1)

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_GetMe__should_return_correct_user(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(&testUser, nil).Times(1)
	router.GetMe(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes getMeRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	testUser.Password = actualRes.User.Password
	assert.Equal(t, testUser, actualRes.User)
}

func Test_Login__should_return_401_when_users_email_not_verified(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "supersecret",
	})

	testUser.EmailVerified = false

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), gomock.Any()).
		Return(&testUser, nil).Times(1)

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_Login__should_return_500_when_making_JWT_token_returns_err(t *testing.T) {
	// leaving env var JWT_SECRET undefined to case NewJWT to throw error
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "",
	})

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), gomock.Any()).
		Return(&testUser, nil).Times(1)

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Login__should_return_401_when_users_password_is_incorrect(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{})

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), gomock.Any()).
		Return(&testUser, nil).Times(1)

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password1232")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Login(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_Register__should_return_400_if_name_is_unspecified(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_Register__should_return_400_if_email_is_unspecified(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_Register__should_return_400_if_password_is_unspecified(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_Register__should_return_400_if_email_is_taken(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, nil).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_Register__should_return_500_if_GetUserReturns_err_that_is_not_ErrNotFound(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, errors.New("service err")).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Register__should_return_500_if_CreateUser_returns_error(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, services.ErrNotFound).Times(1)
	mockUService.EXPECT().CreateUser(gomock.Any(), "John Doe", "john@doe.com", gomock.Not(gomock.Eq("password123")), common.AuthLevel(0)).Return(nil, errors.New("service err")).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Register__should_return_500_and_delete_user_if_creating_email_JWT_fails(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "",
	})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, services.ErrNotFound).Times(1)
	mockUService.EXPECT().CreateUser(gomock.Any(), "John Doe", "john@doe.com", gomock.Not(gomock.Eq("password123")), common.AuthLevel(0)).Return(&testUser, nil).Times(1)
	mockUService.EXPECT().DeleteUserWithEmail(gomock.Any(), "john@doe.com").Return(nil).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Register__should_return_500_and_delete_user_if_sending_email_fails(t *testing.T) {
	mockUService, mockEService, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "supersecret",
	})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, services.ErrNotFound).Times(1)
	mockUService.EXPECT().CreateUser(gomock.Any(), "John Doe", "john@doe.com", gomock.Not(gomock.Eq("password123")), common.AuthLevel(0)).Return(&testUser, nil).Times(1)
	mockUService.EXPECT().DeleteUserWithEmail(gomock.Any(), "john@doe.com").Return(nil).Times(1)
	mockEService.EXPECT().SendEmailVerificationEmail(gomock.Any(), gomock.Any()).Return(errors.New("service err")).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_Register__should_return_200_and_correct_user(t *testing.T) {
	mockUService, mockEService, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "supersecret",
	})

	data := url.Values{}
	data.Add("name", "John Doe")
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "john@doe.com").Return(nil, services.ErrNotFound).Times(1)
	mockUService.EXPECT().CreateUser(gomock.Any(), "John Doe", "john@doe.com", gomock.Not(gomock.Eq("password123")), common.AuthLevel(0)).Return(&testUser, nil).Times(1)
	mockUService.EXPECT().DeleteUserWithEmail(gomock.Any(), "john@doe.com").Return(nil).Times(1)
	mockEService.EXPECT().SendEmailVerificationEmail(gomock.Any(), gomock.Any()).Return(nil).Times(1)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.Register(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes registerRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, testUser.ID, actualRes.User.ID)
}

func Test_VerifyEmail(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantResCode int
		prep        func(userID string, mockUService *mock_services.MockUserService)
	}{
		{
			name:        "should return 401 when no token is specified",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:        "should return 401 when token is invalid",
			token:       "notvalidtoken",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:  "should return 500 when email service returns error",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
			prep: func(userID string, mockUService *mock_services.MockUserService) {
				mockUService.EXPECT().UpdateUserWithID(gomock.Any(), userID, map[string]interface{}{
					"email_verified": true,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 200 when everything is alright",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
			prep: func(userID string, mockUService *mock_services.MockUserService) {
				mockUService.EXPECT().UpdateUserWithID(gomock.Any(), userID, map[string]interface{}{
					"email_verified": true,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
				environment.JWTSecret: "testsecret",
			})
			if tt.prep != nil {
				tt.prep(testUser.ID.Hex(), mockUService)
			}

			req := httptest.NewRequest("GET", fmt.Sprintf("/test?token=%s", tt.token), nil)
			testCtx.Request = req

			router.VerifyEmail(testCtx)
			assert.Equal(t, tt.wantResCode, w.Code)
		})
	}
}

func Test_VerifyEmail(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantResCode int
		prep        func(userID string, mockUService *mock_services.MockUserService)
	}{
		{
			name:        "should return 401 when no token is specified",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:        "should return 401 when token is invalid",
			token:       "notvalidtoken",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:  "should return 500 when email service returns error",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
			prep: func(userID string, mockUService *mock_services.MockUserService) {
				mockUService.EXPECT().UpdateUserWithID(gomock.Any(), userID, map[string]interface{}{
					"email_verified": true,
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:  "should return 200 when everything is alright",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
			prep: func(userID string, mockUService *mock_services.MockUserService) {
				mockUService.EXPECT().UpdateUserWithID(gomock.Any(), userID, map[string]interface{}{
					"email_verified": true,
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUService, _, w, testCtx, _, router, testUser, _ := setupTest(t, map[string]string{
				environment.JWTSecret: "testsecret",
			})
			if tt.prep != nil {
				tt.prep(testUser.ID.Hex(), mockUService)
			}

			req := httptest.NewRequest("GET", fmt.Sprintf("/test?token=%s", tt.token), nil)
			testCtx.Request = req

			router.VerifyEmail(testCtx)
			assert.Equal(t, tt.wantResCode, w.Code)
		})
	}
}

func Test_AuthLevelVerifierFactory__should_return_middleware(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		givenAuthLevel common.AuthLevel
		wantNextCalled bool
		wantAuthLevel  common.AuthLevel
		wantResCode    int
	}{
		{
			name:        "that returns 401 when given token is invalid",
			token:       "not valid token",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:        "that returns 401 when given token is an email token",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
			wantResCode: http.StatusUnauthorized,
		},
		{
			name:           "that returns 401 when auth level is too low",
			givenAuthLevel: 0,
			wantAuthLevel:  3,
			wantResCode:    http.StatusUnauthorized,
		},
		{
			name:           "that returns 200 when auth level is equal to required",
			givenAuthLevel: 3,
			wantAuthLevel:  3,
			wantResCode:    http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "that returns 200 when auth level is above required",
			givenAuthLevel: 4,
			wantAuthLevel:  3,
			wantResCode:    http.StatusOK,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, w, testCtx, testServer, router, _, _ := setupTest(t, map[string]string{
				environment.JWTSecret: "testsecret",
			})

			req := httptest.NewRequest(http.MethodPost, "/test", nil)
			if tt.token == "" {
				testUser := entities.User{
					AuthLevel: tt.givenAuthLevel,
					ID:        primitive.NewObjectID(),
				}
				token, err := auth.NewJWT(testUser, 100, 0, auth.Auth, []byte("testsecret"))
				assert.NoError(t, err)
				req.Header.Set(authHeaderName, token)
			} else {
				req.Header.Set(authHeaderName, tt.token)
			}
			testCtx.Request = req

			nextMiddlewareCalled := false

			testServer.RouterGroup.POST("/test",
				router.AuthLevelVerifierFactory(tt.wantAuthLevel),
				func(ctx *gin.Context) {
					nextMiddlewareCalled = true
					claimsInterface, exists := ctx.Get(authClaimsKeyInCtx)
					assert.True(t, exists)
					_, ok := claimsInterface.(*auth.Claims)
					assert.True(t, ok)
				})
			testServer.ServeHTTP(w, req)

			assert.Equal(t, tt.wantNextCalled, nextMiddlewareCalled)
			assert.Equal(t, tt.wantResCode, w.Code)
		})
	}
}

func Test_PutMe(t *testing.T) {
	tests := []struct {
		name        string
		userName    string
		teamID      string
		prep        func(*testSetup)
		wantResCode int
	}{
		{
			name:        "should return 400 when neither team nor name provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:     "should return 400 when auth claims are missing from request's context",
			userName: "testname",
			teamID:   "test team",
			prep: func(setup *testSetup) {
				setup.testCtx.Set(authClaimsKeyInCtx, nil)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when team id is invalid",
			teamID: "test team",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "test team").
					Return(nil, services.ErrInvalidID).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 400 when team with given id doesn't exist",
			teamID: "test team",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "test team").
					Return(nil, services.ErrNotFound).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:   "should return 500 when query for team fails",
			teamID: "test team",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "test team").
					Return(nil, errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 500 when query to update user fails",
			userName: "test name",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"name": "test name",
				}).Return(errors.New("service err")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:     "should return 200 when successfully updating user's name",
			userName: "test name",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"name": "test name",
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:   "should return 200 when successfully updating user's team",
			teamID: "test team",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "test team").
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": "test team",
				}).Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:     "should return 200 when successfully updating both user's name and team",
			teamID:   "test team",
			userName: "test name",
			prep: func(setup *testSetup) {
				setup.mockTService.EXPECT().GetTeamWithID(gomock.Any(), "test team").
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().UpdateUserWithID(gomock.Any(), setup.testUser.ID.Hex(), map[string]interface{}{
					"team": "test team",
					"name": "test name",
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
			data.Add("name", tt.userName)
			data.Add("team", tt.teamID)

			req := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			setup.testCtx.Request = req

			setup.router.PutMe(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}
