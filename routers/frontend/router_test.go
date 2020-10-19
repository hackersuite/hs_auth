package frontend

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/routers/common"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
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
	mockAuthorizer.EXPECT().GetAuthorizedResources(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

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
	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()

	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	setup.testCtx.Request.AddCookie(&http.Cookie{
		Name:   authCookieName,
		Value:  testAuthToken,
		MaxAge: 1000,
	})
	setup.mockAuthorizer.EXPECT().GetAuthorizedResources(setup.testCtx, testAuthToken, gomock.Any()).
		Return(nil, nil).Times(1)

	setup.router.HandleUnauthorized(setup.testCtx)

	assert.Equal(t, http.StatusUnauthorized, setup.w.Code)
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

func Test_renderPage__omits_component_with_failing_data_provider(t *testing.T) {
	testComponent := frontendComponent{
		name: "testComponent",
		dataProvider: func(*gin.Context, *frontendRouter) (interface{}, error) {
			return nil, errors.New("data provider err")
		},
	}

	testPage, err := newFrontendPage("testPage", "login.gohtml", frontendComponents{testComponent})
	assert.NoError(t, err)

	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()
	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	setup.testCtx.Request.AddCookie(&http.Cookie{
		Name:   authCookieName,
		Value:  testAuthToken,
		MaxAge: 1000,
	})

	setup.mockAuthorizer.EXPECT().GetAuthorizedResources(setup.testCtx, testAuthToken, []authCommon.UniformResourceIdentifier{testPage.componentURIs[0]}).
		Return(authCommon.UniformResourceIdentifiers{testPage.componentURIs[0]}, nil).Times(1)

	setup.router.renderPage(setup.testCtx, testPage, http.StatusOK, nil, "")

	assert.Equal(t, http.StatusOK, setup.w.Code)
}

func Test_renderPage__returns_401_when_authorizer_returns_ErrInvalidToken(t *testing.T) {
	testPage, err := newFrontendPage("testPage", "login.gohtml", nil)
	assert.NoError(t, err)

	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()
	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	setup.testCtx.Request.AddCookie(&http.Cookie{
		Name:   authCookieName,
		Value:  testAuthToken,
		MaxAge: 1000,
	})

	setup.mockAuthorizer.EXPECT().GetAuthorizedResources(setup.testCtx, testAuthToken, []authCommon.UniformResourceIdentifier{}).
		Return(nil, authCommon.ErrInvalidToken).Times(1)

	setup.router.renderPage(setup.testCtx, testPage, http.StatusOK, nil, "")

	assert.Equal(t, http.StatusUnauthorized, setup.w.Code)
}

func Test_renderPage__returns_500_when_authorizer_returns_unkown_error(t *testing.T) {
	testPage, err := newFrontendPage("testPage", "login.gohtml", nil)
	assert.NoError(t, err)

	setup := setupTest(t, nil, 0)
	defer setup.ctrl.Finish()
	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	setup.testCtx.Request.AddCookie(&http.Cookie{
		Name:   authCookieName,
		Value:  testAuthToken,
		MaxAge: 1000,
	})

	setup.mockAuthorizer.EXPECT().GetAuthorizedResources(setup.testCtx, testAuthToken, []authCommon.UniformResourceIdentifier{}).
		Return(nil, errors.New("authorizer err")).Times(1)

	setup.router.renderPage(setup.testCtx, testPage, http.StatusOK, nil, "")

	assert.Equal(t, http.StatusInternalServerError, setup.w.Code)
}
