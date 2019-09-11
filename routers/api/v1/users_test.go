package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/unicsmcr/hs_auth/services"

	"github.com/unicsmcr/hs_auth/utils/auth"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"gopkg.in/dgrijalva/jwt-go.v3"

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

func setupTest(t *testing.T, envVars map[string]string) (*mock_services.MockUserService, *mock_services.MockEmailService, *httptest.ResponseRecorder, *gin.Context, *gin.Engine, APIV1Router, entities.User, string) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockESercive := mock_services.NewMockEmailService(ctrl)
	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	restoreVars := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restoreVars()
	router := NewAPIV1Router(zap.NewNop(), nil, mockUService, mockESercive, env)
	testUser := entities.User{
		AuthLevel: 3,
		ID:        primitive.NewObjectID(),
	}
	var token string
	if env.Get(environment.JWTSecret) != "" {
		var err error
		token, err = auth.NewJWT(testUser, 100, []byte(env.Get(environment.JWTSecret)))
		assert.NoError(t, err)
	}

	return mockUService, mockESercive, w, testCtx, testServer, router, testUser, token
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
	req.Header.Set("Authorization", token)
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
	req.Header.Set("Authorization", token)
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
		GetUserWithEmailAndPassword(gomock.Any(), "john@doe.com", "password123").
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

	var claims common.AuthClaims
	_, err = jwt.ParseWithClaims(actualRes.Token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte("testsecret"), nil
	})
	assert.NoError(t, err)
	assert.Equal(t, testUser.ID.Hex(), claims.Id)
	assert.Equal(t, testUser.AuthLevel, claims.AuthLevel)

	assert.NotNil(t, auth.GetJWTClaims(actualRes.Token, []byte("testsecret")))
	assert.Equal(t, testUser, actualRes.User)
}

func Test_Login__should_return_500_when_user_service_returns_error(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().
		GetUserWithEmailAndPassword(gomock.Any(), "john@doe.com", "password123").
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

func Test_Login__should_return_StatusBadRequest_when_invalid_credentials_are_provided(t *testing.T) {
	mockUService, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})
	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	mockUService.EXPECT().GetUserWithEmailAndPassword(gomock.Any(), "john@doe.com", "password123").
		Return(nil, services.ErrNotFound).Times(1)

	router.Login(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes loginRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, actualRes.Status)
	assert.Equal(t, "user not found", actualRes.Err)
}

func Test_Verify__should_return_StatusOK_for_valid_token(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.Verify(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_Verify__should_return_StatusUnauthorized_for_invalid_token(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token+"some text")
	testCtx.Request = req

	router.Verify(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_GetMe__should_return_401_if_auth_token_is_empty(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Del("Authorization")
	testCtx.Request = req

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_GetMe__should_return_401_if_auth_token_is_invalid(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token+"some text")
	testCtx.Request = req

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_GetMe__should_return_400_if_user_in_token_doesnt_exist(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token)

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(nil, services.ErrNotFound).Times(1)
	testCtx.Request = req

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_GetMe__should_return_500_if_user_service_returns_err(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token)

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(nil, errors.New("service err")).Times(1)
	testCtx.Request = req

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_GetMe__should_return_correct_user(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token)

	mockUService.EXPECT().GetUserWithID(gomock.Any(), testUser.ID.Hex()).Return(&testUser, nil).Times(1)
	testCtx.Request = req

	router.GetMe(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes getMeRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, testUser, actualRes.User)
}

func Test_PutMe__should_return_400_when_email_and_team_is_not_provided(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	data := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	router.PutMe(testCtx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func Test_PutMe__should_return_401_if_auth_token_is_invalid(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	data := url.Values{}
	data.Add("name", "testname")
	data.Add("team", "testteam")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Authorization", token+"some text")
	testCtx.Request = req

	router.PutMe(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_PutMe__should_return_500_when_user_service_returns_error(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().UpdateUserWithID(gomock.Any(), testUser.ID.Hex(), map[string]interface{}{
		"name": "testname",
	}).Return(errors.New("service err")).Times(1)

	data := url.Values{}
	data.Add("name", "testname")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.PutMe(testCtx)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func Test_PutMe__should_set_the_users_name_to_required_value(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().UpdateUserWithID(gomock.Any(), testUser.ID.Hex(), map[string]interface{}{
		"name": "testname",
	}).Return(nil).Times(1)

	data := url.Values{}
	data.Add("name", "testname")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.PutMe(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_PutMe__should_set_the_users_team_to_required_value(t *testing.T) {
	mockUService, _, w, testCtx, _, router, testUser, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	mockUService.EXPECT().UpdateUserWithID(gomock.Any(), testUser.ID.Hex(), map[string]interface{}{
		"team": "testteam",
	}).Return(nil).Times(1)

	data := url.Values{}
	data.Add("team", "testteam")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.PutMe(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_GetUsers__should_return_401_if_auth_token_is_invalid(t *testing.T) {
	_, _, w, testCtx, _, router, _, token := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", token+"some text")
	testCtx.Request = req

	router.GetUsers(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func Test_GetUsers__should_return_401_if_auth_level_is_too_low(t *testing.T) {
	_, _, w, testCtx, _, router, _, _ := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	token, err := auth.NewJWT(entities.User{
		AuthLevel: common.Volunteer,
		ID:        primitive.NewObjectID(),
	}, 100, []byte("testsecret"))
	assert.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.GetUsers(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
