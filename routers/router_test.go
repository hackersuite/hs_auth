package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/unicsmcr/hs_auth/testutils"

	mock_v1 "github.com/unicsmcr/hs_auth/mocks/routers/api/v1"

	"github.com/gin-gonic/gin"

	"github.com/golang/mock/gomock"

	"go.uber.org/zap"
)

func Test_RegisterRoutes__should_register_required_routes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockAPIV1Router := mock_v1.NewMockAPIV1Router(ctrl)

	// checking APIV1Router gets registered on /api/v1
	mockAPIV1Router.EXPECT().RegisterRoutes(testutils.RouterGroupMatcher{Path: "/api/v1"}).Times(1)

	router := NewMainRouter(zap.NewNop(), mockAPIV1Router)

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
