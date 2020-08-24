package v2

import (
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApiV2Router_RegisterRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	router := &apiV2Router{
		logger:     zap.NewNop(),
		authorizer: mockAuthorizer,
	}
	mockAuthMiddlewareCall(router, mockAuthorizer, router.GetUsers)
	mockAuthMiddlewareCall(router, mockAuthorizer, router.GetAuthorizedResources)
	mockAuthMiddlewareCall(router, mockAuthorizer, router.CreateServiceToken)
	w := httptest.NewRecorder()
	_, testServer := gin.CreateTestContext(w)
	router.RegisterRoutes(&testServer.RouterGroup)

	tests := []struct {
		route  string
		method string
	}{
		{
			route:  "/",
			method: http.MethodGet,
		},
		{
			route:  "/users",
			method: http.MethodGet,
		},
		{
			route:  "/users",
			method: http.MethodPost,
		},
		{
			route:  "/users/login",
			method: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.route, nil)

			testServer.ServeHTTP(w, req)

			// making sure route is defined
			assert.NotEqual(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestApiV2Router_GetResourcePath(t *testing.T) {
	router := &apiV2Router{}
	assert.Equal(t, "hs:hs_auth:api:v2", router.GetResourcePath())
}

func TestApiV2Router_GetAuthToken(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	token := "test_token"
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(authTokenHeader, token)
	ctx.Request = req
	router := &apiV2Router{}

	actualToken, err := router.GetAuthToken(ctx)
	assert.NoError(t, err)
	assert.Equal(t, token, actualToken)
}

func TestApiV2Router_HandleUnauthorized(t *testing.T) {
	router := &apiV2Router{}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	router.HandleUnauthorized(ctx)
	assert.True(t, ctx.IsAborted())
}

func mockAuthMiddlewareCall(router APIV2Router, mockAuthorizer *mock_v2.MockAuthorizer, handler gin.HandlerFunc) {
	mockAuthorizer.EXPECT().WithAuthMiddleware(router, gomock.All(testutils.NewHandlerFuncMatcher(handler))).Return(
		func(ctx *gin.Context) {
			handler(ctx)
			return
		})
}
