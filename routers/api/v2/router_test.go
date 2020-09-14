package v2

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

//func setupAuthorizerTest(t *testing.T) *authorizerTestSetup {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
//	router := &apiV2Router{authorizer: mockAuthorizer}
//
//	w := httptest.NewRecorder()
//	testCtx, _ := gin.CreateTestContext(w)
//	req := httptest.NewRequest(http.MethodGet, "/test?from=[hs:hs_application,hs:hs_auth:api]", nil)
//	req.Header.Set(authTokenHeader, "test_token")
//	testCtx.Request = req
//
//	return &authorizerTestSetup{
//		router:       	router,
//		w:            	w,
//		testCtx:      	testCtx,
//		mockAuthorizer: mockAuthorizer,
//	}
//}

func TestApiV2Router_RegisterRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)
	mockUService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidToken)
	mockTService.EXPECT().GetTeamWithID(gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidToken)

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
			route:  "/users/123",
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
		// TODO: add missing test cases for token routes
		{
			route:  "/teams",
			method: http.MethodGet,
		},
		{
			route:  "/teams/123",
			method: http.MethodGet,
		},
		{
			route:  "/teams",
			method: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s:%s", tt.method, tt.route), func(t *testing.T) {
			router := &apiV2Router{
				logger:      zap.NewNop(),
				authorizer:  mockAuthorizer,
				userService: mockUService,
				teamService: mockTService,
			}
			w := httptest.NewRecorder()
			_, testServer := gin.CreateTestContext(w)

			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetUsers)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetUser)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetAuthorizedResources)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.CreateServiceToken)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetTeams)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetTeam)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.CreateTeam)

			router.RegisterRoutes(&testServer.RouterGroup)

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

	actualToken := router.GetAuthToken(ctx)
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
