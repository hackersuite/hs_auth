package v2

import (
	"fmt"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	common2 "github.com/unicsmcr/hs_auth/routers/common"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

func TestApiV2Router_RegisterRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTService := mock_services.NewMockTeamService(ctrl)
	mockTokenService := mock_services.NewMockTokenService(ctrl)
	mockEService := mock_services.NewMockEmailServiceV2(ctrl)
	mockUService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidToken).AnyTimes()
	mockTService.EXPECT().GetTeamWithID(gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidToken)
	mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).Return(primitive.ObjectID{}, common.ErrInvalidTokenType)
	mockTokenService.EXPECT().CreateServiceToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidToken)
	mockAuthorizer.EXPECT().InvalidateServiceToken(gomock.Any(), gomock.Any()).Return(services.ErrInvalidID)
	mockUService.EXPECT().UpdateUserWithID(gomock.Any(), gomock.Any(), gomock.Any()).Return(services.ErrInvalidID)

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
			route:  "/users/123/role",
			method: http.MethodPut,
		},
		{
			route:  "/users/123/permissions",
			method: http.MethodPut,
		},
		{
			route:  "/users/me/team",
			method: http.MethodPut,
		},
		{
			route:  "/users/me/team",
			method: http.MethodDelete,
		},
		{
			route:  "/users",
			method: http.MethodPost,
		},
		{
			route:  "/users/login",
			method: http.MethodPost,
		},
		{
			route:  "/users/123/password",
			method: http.MethodPut,
		},
		{
			route:  "/users/123/password/resetEmail",
			method: http.MethodGet,
		},
		{
			route:  "/users/123/email/verify",
			method: http.MethodPut,
		},
		{
			route:  "/users/123/email/verify",
			method: http.MethodGet,
		},
		{
			route:  "/tokens/service",
			method: http.MethodPost,
		},
		{
			route:  "/tokens/service/testMe",
			method: http.MethodDelete,
		},
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
				logger:       zap.NewNop(),
				authorizer:   mockAuthorizer,
				userService:  mockUService,
				teamService:  mockTService,
				tokenService: mockTokenService,
				emailService: mockEService,
				cfg:          &config.AppConfig{},
			}
			w := httptest.NewRecorder()
			_, testServer := gin.CreateTestContext(w)

			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetUsers)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetUser)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.SetRole)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.SetSpecialPermissions)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.SetPassword)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetPasswordResetEmail)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetAuthorizedResources)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.CreateServiceToken)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.InvalidateServiceToken)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetTeams)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.GetTeam)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.CreateTeam)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.SetTeam)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.RemoveFromTeam)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.VerifyEmail)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.ResendEmailVerification)

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
	assert.Equal(t, common2.ApiV2ResourcePath, router.GetResourcePath())
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
