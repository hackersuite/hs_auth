package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"

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

func setupTest(t *testing.T, envVars map[string]string) (*mock_services.MockUserService, *httptest.ResponseRecorder, *gin.Context, *gin.Engine, APIV1Router) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	restoreVars := testutils.SetEnvVars(envVars)
	env := environment.NewEnv(zap.NewNop())
	restoreVars()
	router := NewAPIV1Router(zap.NewNop(), mockUService, env)

	return mockUService, w, testCtx, testServer, router
}

func Test_GetUsers__should_call_GetUsers_on_UserService(t *testing.T) {
	mockUService, w, testCtx, _, router := setupTest(t, nil)

	expectedRes := getUsersRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: []entities.User{entities.User{Name: "Bob Tester"}},
	}
	mockUService.EXPECT().GetUsers(gomock.Any()).Return(expectedRes.Users, nil).Times(1)

	router.GetUsers(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes getUsersRes
	err = json.Unmarshal([]byte(actualResStr), &actualRes)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedRes, actualRes)
}

func Test_GetUsers__should_return_error_when_UserService_returns_error(t *testing.T) {
	mockUService, w, testCtx, _, router := setupTest(t, nil)

	expectedAPIError := models.NewAPIError(http.StatusInternalServerError, "service err")

	mockUService.EXPECT().GetUsers(gomock.Any()).Return(nil, errors.New(expectedAPIError.Err)).Times(1)

	router.GetUsers(testCtx)

	actualResStr, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	var actualRes models.APIError
	err = json.Unmarshal([]byte(actualResStr), &actualRes)
	assert.NoError(t, err)

	assert.Equal(t, expectedAPIError.Status, w.Code)
	assert.Equal(t, expectedAPIError, actualRes)
}

func Test_Login__should_call_UserService_and_return_correct_token(t *testing.T) {
	mockUService, w, testCtx, _, router := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 5,
	}

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

	assert.True(t, auth.IsValidJWT(actualRes.Token, []byte("testsecret")))
}

func Test_Login__should_return_StatusBadRequest_when_no_email_is_provided(t *testing.T) {
	_, w, testCtx, _, router := setupTest(t, map[string]string{
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
	_, w, testCtx, _, router := setupTest(t, map[string]string{
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
	mockUService, w, testCtx, _, router := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})
	data := url.Values{}
	data.Add("email", "john@doe.com")
	data.Add("password", "password123")

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	testCtx.Request = req

	mockUService.EXPECT().GetUserWithEmailAndPassword(gomock.Any(), "john@doe.com", "password123").
		Return(nil, mongo.ErrNoDocuments).Times(1)

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
	_, w, testCtx, _, router := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	testUser := entities.User{
		AuthLevel: 3,
		ID:        primitive.NewObjectID(),
	}

	token, err := auth.NewJWT(testUser, 100, []byte("testsecret"))
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token)
	testCtx.Request = req

	router.Verify(testCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func Test_Verify__should_return_StatusUnauthorized_for_invalid_token(t *testing.T) {
	_, w, testCtx, _, router := setupTest(t, map[string]string{
		environment.JWTSecret: "testsecret",
	})

	testUser := entities.User{
		AuthLevel: 3,
		ID:        primitive.NewObjectID(),
	}

	token, err := auth.NewJWT(testUser, 100, []byte("testsecret"))
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/verify", nil)
	req.Header.Set("Authorization", token+"some text")
	testCtx.Request = req

	router.Verify(testCtx)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
