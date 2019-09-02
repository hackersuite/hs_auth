package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/entities"

	"github.com/golang/mock/gomock"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
)

func setupTest(t *testing.T) (*mock_services.MockUserService, *httptest.ResponseRecorder, *gin.Context, *gin.Engine, APIV1Router) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	w := httptest.NewRecorder()
	testCtx, testServer := gin.CreateTestContext(w)
	router := NewAPIV1Router(zap.NewNop(), mockUService, nil)

	return mockUService, w, testCtx, testServer, router
}

func Test_GetUsers__should_call_GetUsers_on_UserService(t *testing.T) {
	mockUService, w, testCtx, _, router := setupTest(t)

	testUsers := []entities.User{entities.User{Name: "Bob Tester"}}
	mockUService.EXPECT().GetUsers(gomock.Any()).Return(testUsers, nil).Times(1)

	router.GetUsers(testCtx)

	testUsersJSON, err := json.Marshal(testUsers)
	assert.NoError(t, err)

	actualUsersString, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, string(testUsersJSON), actualUsersString)
}

func Test_GetUsers__should_return_error_when_UserService_returns_error(t *testing.T) {
	mockUService, w, testCtx, _, router := setupTest(t)

	expectedAPIError := models.NewAPIError(http.StatusInternalServerError, "service err")

	mockUService.EXPECT().GetUsers(gomock.Any()).Return(nil, errors.New(expectedAPIError.Err)).Times(1)

	router.GetUsers(testCtx)

	expectedAPIErrorString, err := json.Marshal(expectedAPIError)
	assert.NoError(t, err)

	actualAPIErorString, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	assert.Equal(t, expectedAPIError.Status, w.Code)
	assert.Equal(t, string(expectedAPIErrorString), actualAPIErorString)
}
