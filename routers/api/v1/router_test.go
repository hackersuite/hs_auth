package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"

	mock_services "github.com/unicsmcr/hs_auth/mocks/services"

	"github.com/golang/mock/gomock"

	"go.uber.org/zap"
)

func Test_RegisterRoutes__should_register_required_routes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockUserService := mock_services.NewMockUserService(ctrl)

	mockUserService.EXPECT().GetUsers(gomock.Any()).AnyTimes()
	mockUserService.EXPECT().GetUserWithEmailAndPassword(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	router := NewAPIV1Router(zap.NewNop(), mockUserService)

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
			route:  "/users/login",
			method: http.MethodPost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, testServer := gin.CreateTestContext(w)

			router.RegisterRoutes(&testServer.RouterGroup)

			req := httptest.NewRequest(tt.method, tt.route, nil)

			testServer.ServeHTTP(w, req)

			// making sure route is defined
			assert.NotEqual(t, http.StatusNotFound, w.Code)
		})
	}
}
