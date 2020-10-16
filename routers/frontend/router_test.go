package frontend

import (
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	"github.com/unicsmcr/hs_auth/routers/common"
	"github.com/unicsmcr/hs_auth/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
)

const testAuthToken = "authToken"

func Test_RegisterRoutes__should_register_required_routes(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{
		"JWT_SECRET": "verysecret",
	})
	env := environment.NewEnv(zap.NewNop())
	restoreVars()

	ctrl := gomock.NewController(t)
	mockUserService := mock_services.NewMockUserService(ctrl)
	mockEmailService := mock_services.NewMockEmailService(ctrl)
	mockTeamService := mock_services.NewMockTeamService(ctrl)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)

	mockUserService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).Return(nil, services.ErrInvalidID).AnyTimes()
	mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).Return(primitive.ObjectID{}, authCommon.ErrInvalidToken).AnyTimes()

	router := &frontendRouter{
		logger:       zap.NewNop(),
		cfg:          &config.AppConfig{Name: "test"},
		env:          env,
		userService:  mockUserService,
		teamService:  mockTeamService,
		emailService: mockEmailService,
		authorizer:   mockAuthorizer,
	}
	emailVerificationRouter := &emailVerificationRouter{*router}

	tests := []struct {
		route  string
		method string
	}{
		{
			route:  "/",
			method: http.MethodGet,
		},
		{
			route:  "/login",
			method: http.MethodGet,
		},
		{
			route:  "/login",
			method: http.MethodPost,
		},
		{
			route:  "/register",
			method: http.MethodGet,
		},
		{
			route:  "/register",
			method: http.MethodPost,
		},
		{
			route:  "/forgotpwd",
			method: http.MethodGet,
		},
		{
			route:  "/forgotpwd",
			method: http.MethodPost,
		},
		{
			route:  "/resetpwd",
			method: http.MethodGet,
		},
		{
			route:  "/resetpwd",
			method: http.MethodPost,
		},
		{
			route:  "/verifyemail",
			method: http.MethodGet,
		},
		{
			route:  "/verifyemail/resend",
			method: http.MethodGet,
		},
		{
			route:  "/emailunverified",
			method: http.MethodGet,
		},
		{
			route:  "/team/create",
			method: http.MethodPost,
		},
		{
			route:  "/team/join",
			method: http.MethodPost,
		},
		{
			route:  "/team/leave",
			method: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, testServer := gin.CreateTestContext(w)

			mockAuthMiddlewareCall(router, mockAuthorizer, router.ResetPassword)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.ProfilePage)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.Logout)
			mockAuthMiddlewareCall(emailVerificationRouter, mockAuthorizer, router.VerifyEmail)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.VerifyEmailResend)
			mockAuthMiddlewareCall(router, mockAuthorizer, router.EmailUnverifiedPage)

			router.RegisterRoutes(&testServer.RouterGroup)

			req := httptest.NewRequest(tt.method, tt.route, nil)

			testServer.LoadHTMLGlob("../../templates/*/*.gohtml")
			testServer.ServeHTTP(w, req)

			// making sure route is defined
			assert.NotEqual(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestRouter_GetResourcePath(t *testing.T) {
	router := &frontendRouter{}
	assert.Equal(t, common.FrontendResourcePath, router.GetResourcePath())
}

func TestRouter_GetAuthToken__returns_correct_token(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.AddCookie(&http.Cookie{
		Name:  authCookieName,
		Value: testAuthToken,
	})
	router := &frontendRouter{}

	actualToken := router.GetAuthToken(ctx)
	assert.Equal(t, testAuthToken, actualToken)
}

func TestRouter_GetAuthToken__returns_empty_string_when_token_is_not_set(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	router := &frontendRouter{logger: zap.NewNop()}

	actualToken := router.GetAuthToken(ctx)
	assert.Equal(t, "", actualToken)
}

func TestRouter_HandleUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	router := &frontendRouter{}

	router.HandleUnauthorized(ctx)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.HeaderMap["Location"][0])
}

func mockAuthMiddlewareCall(router Router, mockAuthorizer *mock_v2.MockAuthorizer, handler gin.HandlerFunc) {
	mockAuthorizer.EXPECT().WithAuthMiddleware(router, gomock.Any()).Return(
		func(ctx *gin.Context) {
			handler(ctx)
			return
		})
}

func TestEmailVerificationRouter_GetAuthToken(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test?token=authToken", nil)

	router := emailVerificationRouter{}

	assert.Equal(t, "authToken", router.GetAuthToken(ctx))
}

func TestNewRouter__returns_non_nil(t *testing.T) {
	assert.NotNil(t, NewRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil))
}
