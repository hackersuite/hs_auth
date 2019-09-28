package frontend

import (
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

func Test_RegisterRoutes__should_register_required_routes(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{
		"JWT_SECRET": "verysecret",
	})
	env := environment.NewEnv(zap.NewNop())
	restoreVars()

	ctrl := gomock.NewController(t)
	mockUserService := mock_services.NewMockUserService(ctrl)
	mockEmailService := mock_services.NewMockEmailService(ctrl)

	router := NewRouter(zap.NewNop(), &config.AppConfig{Name: "test"}, env, mockUserService, mockEmailService)

	tests := []struct {
		route  string
		method string
	}{
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
	}

	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, testServer := gin.CreateTestContext(w)

			router.RegisterRoutes(&testServer.RouterGroup)

			req := httptest.NewRequest(tt.method, tt.route, nil)

			testServer.LoadHTMLGlob("../../templates/*/*.gohtml")
			testServer.ServeHTTP(w, req)

			// making sure route is defined
			assert.NotEqual(t, http.StatusNotFound, w.Code)
		})
	}
}
