package v2

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

type tokensTestSetup struct {
	ctrl             *gomock.Controller
	router           APIV2Router
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	testUser         *entities.User
	testCtx          *gin.Context
	w                *httptest.ResponseRecorder
}

func setupTokensTest(t *testing.T) *tokensTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	router := NewAPIV2Router(zap.NewNop(), &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}, mockAuthorizer, mockUService, nil, mockTimeProvider)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	return &tokensTestSetup{
		ctrl:             ctrl,
		router:           router,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		testCtx:          testCtx,
		w:                w,
	}
}

func TestApiV2Router_CreateServiceToken(t *testing.T) {
	tests := []struct {
		name            string
		prep            func(prep *tokensTestSetup)
		testOwner       string
		testAllowedURIs string
		testExpiresAt   string
		wantResCode     int
		wantRes         *serviceTokenRes
	}{
		{
			name:            "should return 200 when request is valid with one allowed URI",
			testOwner:       "hs_application",
			testAllowedURIs: "\"hs:hs_application\"",
			testExpiresAt:   "100",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken("hs_application", gomock.Any(), int64(100)).
					Return("test_token", nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &serviceTokenRes{
				Token: "test_token",
			},
		},
		{
			name:            "should return 200 when request is valid with multiple allowed URIs",
			testOwner:       "hs_application",
			testAllowedURIs: "\"hs:hs_application\",\"hs:hs_hub\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken("hs_application", gomock.Any(), int64(0)).
					Return("test_token", nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &serviceTokenRes{
				Token: "test_token",
			},
		},
		{
			name:            "should return 400 when owner is not provided",
			testAllowedURIs: "\"hs:hs_application\"",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:        "should return 400 when allowedURIs is not provided",
			testOwner:   "hs_application",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:          "should return 400 when expiresAt isn't int64",
			testOwner:     "hs_auth",
			testExpiresAt: "0test",
			wantResCode:   http.StatusBadRequest,
		},
		{
			name:            "should return 400 when allowedURIs are malformed",
			testOwner:       "hs_auth",
			testAllowedURIs: "\"??##test##??\"",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 500 when CreateServiceToken returns unknown error",
			testOwner:       "hs_auth",
			testAllowedURIs: "\"hs:hs_application\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken("hs_auth", gomock.Any(), int64(0)).
					Return("", errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTokensTest(t)
			if tt.prep != nil {
				tt.prep(setup)
			}

			testutils.AddRequestWithFormParamsToCtx(setup.testCtx,
				http.MethodPost,
				map[string]string{
					"owner":       tt.testOwner,
					"allowedURIs": tt.testAllowedURIs,
					"expiresAt":   tt.testExpiresAt,
				},
			)

			setup.router.CreateServiceToken(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			if tt.wantRes != nil {
				var actualRes serviceTokenRes
				err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRes, actualRes)
			}
		})
	}
}

func TestApiV2Router_GetAuthorizedResources(t *testing.T) {
	testUris := []string{"hs:hs_application", "hs:hs_auth:api"}
	var expectedUriRes []v2.UniformResourceIdentifier
	for _, uriString := range testUris {
		uri, _ := v2.NewURIFromString(uriString)
		expectedUriRes = append(expectedUriRes, uri)
	}
	expectedRes := &getAuthorizedResourcesRes{
		AuthorizedUris: expectedUriRes,
	}

	tests := []struct {
		name            string
		prep            func(setup *tokensTestSetup)
		testAllowedURIs string
		wantResCode     int
		wantRes         *getAuthorizedResourcesRes
	}{
		{
			name: "with valid request",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().GetAuthorizedResources(gomock.Any(), gomock.Any()).
					Return(expectedUriRes, nil).Times(1)
			},
			testAllowedURIs: "[hs:hs_auth]",
			wantResCode:     http.StatusOK,
			wantRes:         expectedRes,
		},
		{
			name:        "with no query params",
			wantResCode: http.StatusBadRequest,
			wantRes: &getAuthorizedResourcesRes{
				nil,
			},
		},
		{
			name:            "with malformed encoded uri in request",
			testAllowedURIs: "[%ZZhs%ZZhs_auth::]",
			wantResCode:     http.StatusBadRequest,
			wantRes: &getAuthorizedResourcesRes{
				nil,
			},
		},
		{
			name:            "with malformed uri in request",
			testAllowedURIs: "[hs:hs_auth??##]",
			wantResCode:     http.StatusBadRequest,
			wantRes: &getAuthorizedResourcesRes{
				nil,
			},
		},
		{
			name:            "invalid jwt in req",
			testAllowedURIs: "[hs:hs_auth]",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().GetAuthorizedResources(gomock.Any(), gomock.Any()).
					Return(nil, v2.ErrInvalidToken).Times(1)
			},
			wantResCode: http.StatusUnauthorized,
			wantRes: &getAuthorizedResourcesRes{
				nil,
			},
		},
		{
			name:            "authorizer method returns unknown error",
			testAllowedURIs: "[hs:hs_auth]",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().GetAuthorizedResources(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
			wantRes: &getAuthorizedResourcesRes{
				nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTokensTest(t)

			var queryParams map[string]string
			if len(tt.testAllowedURIs) > 0 {
				queryParams = map[string]string{"from": tt.testAllowedURIs}
			}

			testutils.AddRequestWithUrlParamsToCtx(setup.testCtx, http.MethodGet, queryParams)
			defer setup.ctrl.Finish()

			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.GetAuthorizedResources(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)

			var actualRes getAuthorizedResourcesRes
			err := testutils.UnmarshallResponse(setup.w.Body, &actualRes)
			assert.NoError(t, err)
			assert.Equal(t, *tt.wantRes, actualRes)
		})
	}
}
