package v2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var (
	testTokenId = primitive.NewObjectID()
)

type tokensTestSetup struct {
	ctrl             *gomock.Controller
	router           APIV2Router
	mockTService     *mock_services.MockTokenService
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	testToken        *entities.Token
	testCtx          *gin.Context
	w                *httptest.ResponseRecorder
}

func setupTokensTest(t *testing.T) *tokensTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockTService := mock_services.NewMockTokenService(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	router := NewAPIV2Router(zap.NewNop(), &config.AppConfig{
		AuthTokenLifetime: testAuthTokenLifetime,
	}, mockAuthorizer, nil, nil, mockTService, mockTimeProvider)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)
	testToken := entities.Token{
		ID:  testTokenId,
		JWT: "test_token",
	}

	return &tokensTestSetup{
		ctrl:             ctrl,
		router:           router,
		mockTService:     mockTService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		testToken:        &testToken,
		testCtx:          testCtx,
		w:                w,
	}
}

func TestApiV2Router_CreateServiceToken(t *testing.T) {
	tests := []struct {
		name            string
		prep            func(prep *tokensTestSetup)
		testAllowedURIs string
		testExpiresAt   string
		wantResCode     int
		wantRes         *serviceTokenRes
	}{
		{
			name:            "should return 200 when request is valid with one allowed URI",
			testAllowedURIs: "\"hs:hs_application\"",
			testExpiresAt:   "100",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken(gomock.Any(), gomock.Any(), int64(100)).
					Return(setup.testToken.JWT, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().AddServiceToken(setup.testCtx, gomock.Any(), gomock.Any(), setup.testToken.JWT).
					Return(setup.testToken, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &serviceTokenRes{
				Token: "test_token",
			},
		},
		{
			name:            "should return 200 when request is valid with multiple allowed URIs",
			testAllowedURIs: "\"hs:hs_application\",\"hs:hs_hub\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken(gomock.Any(), gomock.Any(), int64(0)).
					Return(setup.testToken.JWT, nil).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().AddServiceToken(setup.testCtx, gomock.Any(), gomock.Any(), setup.testToken.JWT).
					Return(setup.testToken, nil).Times(1)
			},
			wantResCode: http.StatusOK,
			wantRes: &serviceTokenRes{
				Token: "test_token",
			},
		},
		{
			name:        "should return 400 when allowedURIs is not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:          "should return 400 when expiresAt isn't int64",
			testExpiresAt: "0test",
			wantResCode:   http.StatusBadRequest,
		},
		{
			name:            "should return 400 when allowedURIs are malformed",
			testAllowedURIs: "\"??##test##??\"",
			wantResCode:     http.StatusBadRequest,
		},
		{
			name:            "should return 400 when GetUserIdFromToken returns error",
			testAllowedURIs: "\"hs:hs_application\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).
					Return(primitive.ObjectID{}, errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusBadRequest,
		},
		{
			name:            "should return 500 when CreateServiceToken returns unknown error",
			testAllowedURIs: "\"hs:hs_application\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().CreateServiceToken(gomock.Any(), gomock.Any(), int64(0)).
					Return("", errors.New("random error")).Times(1)
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).
					Return(testUserId, nil).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
		{
			name:            "should return 500 when AddServiceToken returns error",
			testAllowedURIs: "\"hs:hs_application\"",
			prep: func(setup *tokensTestSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(gomock.Any()).
					Return(testUserId, nil).Times(1)
				setup.mockAuthorizer.EXPECT().CreateServiceToken(gomock.Any(), gomock.Any(), int64(0)).
					Return(setup.testToken.JWT, nil).Times(1)
				setup.mockTService.EXPECT().AddServiceToken(setup.testCtx, gomock.Any(), gomock.Any(), setup.testToken.JWT).
					Return(nil, errors.New("random error")).Times(1)
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

func TestApiV2Router_DeleteServiceToken(t *testing.T) {
	tests := []struct {
		name        string
		prep        func(prep *tokensTestSetup)
		tokenId     string
		wantResCode int
	}{
		{
			name:    "should return 2xx when request is valid token id",
			tokenId: testTokenId.Hex(),
			prep: func(setup *tokensTestSetup) {
				setup.mockTService.EXPECT().DeleteServiceToken(setup.testCtx, testTokenId.Hex()).
					Return(nil).Times(1)
			},
			wantResCode: http.StatusOK,
		},
		{
			name:        "should return 400 when token id not provided",
			wantResCode: http.StatusBadRequest,
		},
		{
			name:    "should return 500 when DeleteServiceToken returns unknown error",
			tokenId: testTokenId.Hex(),
			prep: func(setup *tokensTestSetup) {
				setup.mockTService.EXPECT().DeleteServiceToken(setup.testCtx, testTokenId.Hex()).
					Return(errors.New("random error")).Times(1)
			},
			wantResCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTokensTest(t)
			testutils.AddRequestWithFormParamsToCtx(setup.testCtx, http.MethodDelete, nil)
			setup.testCtx.Request.Header.Set(authTokenHeader, testAuthToken)
			testutils.AddUrlParamsToCtx(setup.testCtx, map[string]string{"id": tt.tokenId})
			defer setup.ctrl.Finish()
			if tt.prep != nil {
				tt.prep(setup)
			}

			setup.router.DeleteServiceToken(setup.testCtx)

			assert.Equal(t, tt.wantResCode, setup.w.Code)
		})
	}
}
