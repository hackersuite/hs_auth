package v1

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

func Test_RegisterRoutes__should_register_required_routes(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{
		"JWT_SECRET": "verysecret",
	})
	env := environment.NewEnv(zap.NewNop())
	restoreVars()

	ctrl := gomock.NewController(t)
	mockUserService := mock_services.NewMockUserServiceV2(ctrl)
	mockTeamService := mock_services.NewMockTeamService(ctrl)

	mockUserService.EXPECT().GetUsers(gomock.Any()).AnyTimes()
	mockUserService.EXPECT().GetUserWithEmail(gomock.Any(), gomock.Any()).AnyTimes()
	mockUserService.EXPECT().UpdateUserWithJWT(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockTeamService.EXPECT().GetTeams(gomock.Any()).AnyTimes()

	router := NewAPIV1Router(zap.NewNop(), nil, env, mockUserService, nil, mockTeamService)

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
		{
			route:  "/users/me",
			method: http.MethodGet,
		},
		{
			route:  "/users/me",
			method: http.MethodPut,
		},
		{
			route:  "/users/",
			method: http.MethodPost,
		},
		{
			route:  "/users/email/verify",
			method: http.MethodPost,
		},
		{
			route:  "/teams/",
			method: http.MethodGet,
		},
		{
			route:  "/teams/",
			method: http.MethodPost,
		},
		{
			route:  "/teams/leave",
			method: http.MethodDelete,
		},
		{
			route:  "/teams/123abd/join",
			method: http.MethodPost,
		},
		{
			route:  "/teams/123abd/members",
			method: http.MethodGet,
		},
		{
			route:  "/users/password/reset",
			method: http.MethodGet,
		},
		{
			route:  "/users/password/reset",
			method: http.MethodPut,
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

func Test_RegisterRoutes__should_set_up_required_auth_verification(t *testing.T) {
	restoreVars := testutils.SetEnvVars(map[string]string{
		"JWT_SECRET": "verysecret",
	})
	env := environment.NewEnv(zap.NewNop())
	restoreVars()

	ctrl := gomock.NewController(t)
	mockUserService := mock_services.NewMockUserServiceV2(ctrl)
	mockTeamService := mock_services.NewMockTeamService(ctrl)

	mockUserService.EXPECT().GetUsers(gomock.Any()).AnyTimes()
	mockUserService.EXPECT().GetUserWithJWT(gomock.Any(), gomock.Any()).Return(nil, errors.New("service err")).AnyTimes()
	mockUserService.EXPECT().GetUserWithEmail(gomock.Any(), gomock.Any()).AnyTimes()
	mockUserService.EXPECT().GetUserWithID(gomock.Any(), gomock.Any()).Return(nil, errors.New("service err")).AnyTimes()
	mockUserService.EXPECT().UpdateUserWithJWT(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockTeamService.EXPECT().GetTeams(gomock.Any()).AnyTimes()

	router := NewAPIV1Router(zap.NewNop(), nil, env, mockUserService, nil, mockTeamService)

	tests := []struct {
		route        string
		method       string
		minAuthLevel authlevels.AuthLevel
	}{
		{
			route:        "/users/",
			method:       http.MethodGet,
			minAuthLevel: authlevels.Organizer,
		},
		{
			route:        "/users/me",
			method:       http.MethodGet,
			minAuthLevel: authlevels.Applicant,
		},
		{
			route:        "/users/me",
			method:       http.MethodPut,
			minAuthLevel: authlevels.Applicant,
		},
		{
			route:        "/teams/",
			method:       http.MethodGet,
			minAuthLevel: authlevels.Organizer,
		},
		{
			route:        "/teams/",
			method:       http.MethodPost,
			minAuthLevel: authlevels.Applicant,
		},
		{
			route:        "/teams/leave",
			method:       http.MethodDelete,
			minAuthLevel: authlevels.Applicant,
		},
		{
			route:        "/teams/123abd/join",
			method:       http.MethodPost,
			minAuthLevel: authlevels.Applicant,
		},
		{
			route:        "/teams/123abd/members",
			method:       http.MethodGet,
			minAuthLevel: authlevels.Applicant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			for i := 0; i <= int(tt.minAuthLevel); i++ {
				w := httptest.NewRecorder()
				_, testServer := gin.CreateTestContext(w)

				router.RegisterRoutes(&testServer.RouterGroup)

				token, err := auth.NewJWT(entities.User{
					ID:        primitive.NewObjectID(),
					AuthLevel: authlevels.AuthLevel(i),
				}, time.Now().Unix(), 100, auth.Auth, []byte(env.Get(environment.JWTSecret)))
				assert.NoError(t, err)

				req := httptest.NewRequest(tt.method, tt.route, nil)
				req.Header.Set(authHeaderName, token)

				testServer.ServeHTTP(w, req)

				// making sure route is defined
				if i < int(tt.minAuthLevel) {
					assert.Equal(t, http.StatusUnauthorized, w.Code)
				} else {
					assert.NotEqual(t, http.StatusUnauthorized, w.Code)
				}
			}
		})
	}
}
