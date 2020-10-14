package v2

import (
	"context"
	"fmt"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/entities"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services/mongo"
	"github.com/unicsmcr/hs_auth/utils"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/environment"
	mock_resources "github.com/unicsmcr/hs_auth/mocks/authorization/v2/common"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const (
	testAuthTokenLifetime = 10000000
)

type authorizerTestSetup struct {
	authorizer         Authorizer
	mockTimeProvider   *mock_utils.MockTimeProvider
	mockRouterResource *mock_resources.MockRouterResource
	mockTokenService   *mock_services.MockTokenService
	mockUserService    *mock_services.MockUserService
	testCtx            *gin.Context
	testCfg            *config.AppConfig
	ctrl               *gomock.Controller
}

type authorizerBenchmarkSetup struct {
	authorizer         Authorizer
	timeProvider       utils.TimeProvider
	mockRouterResource *mock_resources.MockRouterResource
	tRepo              *repositories.TokenRepository
	uRepo              *repositories.UserRepository
	testCtx            *gin.Context
	ctrl               *gomock.Controller
}

var testUserId = primitive.NewObjectID()

func setupAuthorizerTests(t *testing.T, jwtSecret string) authorizerTestSetup {
	restore := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: jwtSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	restore()

	ctrl := gomock.NewController(t)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)
	mockRouterResource := mock_resources.NewMockRouterResource(ctrl)
	mockTokenService := mock_services.NewMockTokenService(ctrl)
	mockUserService := mock_services.NewMockUserService(ctrl)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)
	testutils.AddRequestWithFormParamsToCtx(testCtx, http.MethodGet, nil)

	testURI, _ := common.NewURIFromString("test_role_uri")
	appCfg := &config.AppConfig{
		UserRole: map[role.UserRole]common.UniformResourceIdentifiers{
			role.Unverified: {testURI},
			role.Applicant:  {},
			role.Attendee:   {},
			role.Volunteer:  {},
			role.Organiser:  {},
		},
	}

	return authorizerTestSetup{
		authorizer:         NewAuthorizer(mockTimeProvider, appCfg, env, zap.NewNop(), mockTokenService, mockUserService),
		mockTimeProvider:   mockTimeProvider,
		mockRouterResource: mockRouterResource,
		mockTokenService:   mockTokenService,
		mockUserService:    mockUserService,
		testCtx:            testCtx,
		testCfg:            appCfg,
		ctrl:               ctrl,
	}
}

func setupAuthorizerBenchmarks(b *testing.B, jwtSecret string) authorizerBenchmarkSetup {
	// Prevents gin from spamming the console output
	// Required for 'cob' benchmark result parser to work correctly
	gin.SetMode(gin.ReleaseMode)

	db := testutils.ConnectToIntegrationTestDB(b)

	restore := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: jwtSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	restore()

	ctrl := gomock.NewController(b)
	timeProvider := utils.NewTimeProvider()
	mockRouterResource := mock_resources.NewMockRouterResource(ctrl)

	tokenRepository, err := repositories.NewTokenRepository(db)
	if err != nil {
		panic(err)
	}
	tokenService := mongo.NewMongoTokenService(zap.NewNop(), env, tokenRepository)

	userRepository, err := repositories.NewUserRepository(db)
	if err != nil {
		panic(err)
	}
	userService := mongo.NewMongoUserService(zap.NewNop(), env, nil, userRepository)

	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)
	testutils.AddRequestWithFormParamsToCtx(testCtx, http.MethodGet, nil)

	testRoleURI, _ := common.NewURIFromString("hs")
	appCfg := &config.AppConfig{
		UserRole: map[role.UserRole]common.UniformResourceIdentifiers{
			role.Organiser: {testRoleURI},
		},
	}
	return authorizerBenchmarkSetup{
		authorizer:         NewAuthorizer(timeProvider, appCfg, env, zap.NewNop(), tokenService, userService),
		timeProvider:       timeProvider,
		mockRouterResource: mockRouterResource,
		tRepo:              tokenRepository,
		uRepo:              userRepository,
		testCtx:            testCtx,
		ctrl:               ctrl,
	}
}

func createTestURI(source string) common.UniformResourceIdentifier {
	uri, _ := common.NewURIFromString(source)
	return uri
}

func TestAuthorizer_CreateServiceToken(t *testing.T) {
	testID := primitive.NewObjectID()
	var testTTL int64 = 100
	testTimestamp := time.Now()
	testURI := createTestURI("test")
	testAllowedResources := []common.UniformResourceIdentifier{testURI}

	tests := []struct {
		name   string
		checks func(claims tokenClaims)
	}{
		{
			name: "should use correct IssuedAt",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testTimestamp.Unix(), claims.IssuedAt)
			},
		},
		{
			name: "should use correct ExpiresAt",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testTimestamp.Unix()+testTTL, claims.ExpiresAt)
			},
		},
		{
			name: "should use correct TokenType",
			checks: func(claims tokenClaims) {
				assert.Equal(t, Service, claims.TokenType)
			},
		},
		{
			name: "should use correct AllowedResources",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testAllowedResources, claims.AllowedResources)
			},
		},
	}

	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	setup.mockTimeProvider.EXPECT().Now().Return(testTimestamp).Times(1)
	setup.mockTokenService.EXPECT().CreateServiceToken(setup.testCtx, testID.Hex(), testID.Hex(), gomock.Any()).Return(&entities.ServiceToken{}, nil).Times(1)
	setup.mockTokenService.EXPECT().GenerateServiceTokenID().Return(testID).Times(1)

	token, err := setup.authorizer.CreateServiceToken(setup.testCtx, testID, testAllowedResources, testTimestamp.Unix()+testTTL)
	assert.NoError(t, err)

	claims := extractTokenClaims(t, token, jwtSecret)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checks(claims)
		})
	}
}

func TestAuthorizer_InvalidateServiceToken__should_delete_correct_token(t *testing.T) {
	jwtSecret := "test_secret"
	token := createToken(t, "test_id", nil, 1000, Service, jwtSecret)
	setup := setupAuthorizerTests(t, jwtSecret)
	defer setup.ctrl.Finish()
	setup.mockTokenService.EXPECT().DeleteServiceToken(setup.testCtx, "test_id").Return(nil).Times(1)

	err := setup.authorizer.InvalidateServiceToken(setup.testCtx, token)
	assert.NoError(t, err)
}

func TestAuthorizer_InvalidateServiceToken__should_return_error_when_token_is_invalid(t *testing.T) {
	setup := setupAuthorizerTests(t, "")

	err := setup.authorizer.InvalidateServiceToken(setup.testCtx, "invalid token")
	assert.Error(t, err)
}

func TestAuthorizer_InvalidateServiceToken__should_return_error_when_token_type_is_not_service(t *testing.T) {
	jwtSecret := "test_secret"
	token := createToken(t, "test_id", nil, 1000, User, jwtSecret)
	setup := setupAuthorizerTests(t, jwtSecret)
	defer setup.ctrl.Finish()

	err := setup.authorizer.InvalidateServiceToken(setup.testCtx, token)
	assert.Equal(t, common.ErrInvalidTokenType, errors.Cause(err))
}

func TestAuthorizer_CreateServiceToken_throws_unknown_error(t *testing.T) {
	testID := primitive.NewObjectID()
	var testTTL int64 = 100
	testTimestamp := time.Now()
	testURI := createTestURI("test")
	testAllowedResources := []common.UniformResourceIdentifier{testURI}

	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	setup.mockTimeProvider.EXPECT().Now().Return(testTimestamp).Times(1)
	setup.mockTokenService.EXPECT().CreateServiceToken(setup.testCtx, testID.Hex(), testID.Hex(), gomock.Any()).
		Return(nil, errors.New("random error")).Times(1)
	setup.mockTokenService.EXPECT().GenerateServiceTokenID().Return(testID).Times(1)

	_, err := setup.authorizer.CreateServiceToken(setup.testCtx, testID, testAllowedResources, testTimestamp.Unix()+testTTL)
	assert.Error(t, err)
}

func TestAuthorizer_CreateUserToken(t *testing.T) {
	testUserId := primitive.NewObjectIDFromTimestamp(time.Now())
	var testTTL int64 = 100
	testTimestamp := time.Now()

	tests := []struct {
		name   string
		checks func(claims tokenClaims)
	}{
		{
			name: "should use correct Id",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testUserId.Hex(), claims.Id)
			},
		},
		{
			name: "should use correct IssuedAt",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testTimestamp.Unix(), claims.IssuedAt)
			},
		},
		{
			name: "should use correct ExpiresAt",
			checks: func(claims tokenClaims) {
				assert.Equal(t, testTimestamp.Unix()+testTTL, claims.ExpiresAt)
			},
		},
		{
			name: "should use correct TokenType",
			checks: func(claims tokenClaims) {
				assert.Equal(t, User, claims.TokenType)
			},
		},
	}

	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	setup.mockTimeProvider.EXPECT().Now().Return(testTimestamp).Times(1)

	token, err := setup.authorizer.CreateUserToken(testUserId, testTimestamp.Unix()+testTTL)
	assert.NoError(t, err)

	claims := extractTokenClaims(t, token, jwtSecret)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checks(claims)
		})
	}
}

func TestAuthorizer_GetAuthorizedResources_should_return_correct_uris_when_service_token_is_valid(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	testURI := createTestURI("test")
	token := createToken(t, "testuser", []common.UniformResourceIdentifier{testURI}, int64(100), Service, jwtSecret)
	uris := []common.UniformResourceIdentifier{testURI}

	returnedUris, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.NoError(t, err)

	assert.Equal(t, uris, returnedUris)
}

func TestAuthorizer_GetAuthorizedResources_should_return_correct_uris_when_user_token_is_valid(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	testURI := createTestURI("test")
	token := createToken(t, testUserId.Hex(), []common.UniformResourceIdentifier{testURI}, int64(100), User, jwtSecret)
	uris := []common.UniformResourceIdentifier{testURI}

	setup.mockUserService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
		Return(&entities.User{ID: testUserId, SpecialPermissions: uris, Role: role.Unverified}, nil).Times(1)

	returnedUris, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.NoError(t, err)

	assert.Equal(t, uris, returnedUris)
}

func TestAuthorizer_GetAuthorizedResources_should_return_error_when_user_not_found(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	testURI := createTestURI("test")
	token := createToken(t, testUserId.Hex(), []common.UniformResourceIdentifier{testURI}, int64(100), User, jwtSecret)
	uris := []common.UniformResourceIdentifier{testURI}

	setup.mockUserService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
		Return(nil, errors.New("random error")).Times(1)

	_, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.Error(t, err)
}

func TestAuthorizer_GetAuthorizedResources_should_return_error_when_user_role_not_found(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	testURI := createTestURI("test")
	token := createToken(t, testUserId.Hex(), []common.UniformResourceIdentifier{testURI}, int64(100), User, jwtSecret)
	uris := []common.UniformResourceIdentifier{testURI}

	setup.mockUserService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
		Return(&entities.User{ID: testUserId, SpecialPermissions: uris, Role: "unknown"}, nil).Times(1)

	_, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.Error(t, err)
}

func TestAuthorizer_GetAuthorizedResources_should_merge_user_and_role_permissions(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	testURI := createTestURI("test")
	token := createToken(t, testUserId.Hex(), []common.UniformResourceIdentifier{testURI}, int64(100), User, jwtSecret)
	uris := []common.UniformResourceIdentifier{testURI}

	testPermissions, _ := setup.testCfg.UserRole.GetRolePermissions(role.Unverified)
	setup.mockUserService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
		Return(&entities.User{ID: testUserId, SpecialPermissions: uris, Role: role.Unverified}, nil).Times(1)

	matchedURIs, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, testPermissions)
	assert.NoError(t, err)
	assert.Equal(t, testPermissions, common.UniformResourceIdentifiers(matchedURIs))
}

func TestAuthorizer_GetAuthorizedResources_should_remove_uris_with_invalid_metadata(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	defer setup.ctrl.Finish()
	validUri, err := common.NewURIFromString("test")
	assert.NoError(t, err)
	token := createToken(t, "testuser", []common.UniformResourceIdentifier{validUri}, int64(100), Service, jwtSecret)

	var testTime int64 = 1000
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(testTime, 0)).Times(1)
	invalidMetadataUri, err := common.NewURIFromString(fmt.Sprintf("hs:hs_auth#%s=%d", before, testTime+1))
	assert.NoError(t, err)

	uris := []common.UniformResourceIdentifier{validUri, invalidMetadataUri}

	returnedUris, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.NoError(t, err)

	assert.Equal(t, []common.UniformResourceIdentifier{validUri}, returnedUris)
}

func TestAuthorizer_GetAuthorizedResources_should_ignore_uris_in_token_with_invalid_metadata(t *testing.T) {
	jwtSecret := "test_secret"
	setup := setupAuthorizerTests(t, jwtSecret)
	defer setup.ctrl.Finish()

	var testTime int64 = 1000
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(testTime, 0)).Times(1)
	invalidMetadataUri, err := common.NewURIFromString(fmt.Sprintf("hs:hs_auth#%s=%d", before, testTime+1))
	assert.NoError(t, err)

	token := createToken(t, "testuser", []common.UniformResourceIdentifier{invalidMetadataUri}, int64(100), Service, jwtSecret)

	testUri, err := common.NewURIFromString("hs:hs_auth")
	uris := []common.UniformResourceIdentifier{testUri}

	returnedUris, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, token, uris)
	assert.NoError(t, err)

	assert.Len(t, returnedUris, 0)
}

func TestAuthorizer_GetAuthorizedResources_should_return_err_with_invalid_token(t *testing.T) {
	jwtSecret := "jwtSecret"
	malformedMetadataUri, err := common.NewURIFromString(fmt.Sprintf("hs:hs_auth#%s=notadate", before))
	assert.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		givenUris []common.UniformResourceIdentifier
		wantedErr error
	}{
		{
			name:      "when token is invalid",
			token:     "invalid token",
			wantedErr: common.ErrInvalidToken,
		},
		{
			name:      "when token type is invalid",
			token:     createToken(t, "user id", nil, int64(0), "unknown type", jwtSecret),
			wantedErr: common.ErrInvalidToken,
		},
		{
			name:      "when token is expired",
			token:     createToken(t, "user id", nil, int64(-5), Service, jwtSecret),
			wantedErr: common.ErrInvalidToken,
		},
		{
			name:      "when given URIs contain URI with malformed metadata",
			token:     createToken(t, "user id", nil, int64(0), Service, jwtSecret),
			givenUris: []common.UniformResourceIdentifier{malformedMetadataUri},
			wantedErr: common.ErrInvalidURI,
		},
		{
			name:      "when URIs in token contain URI with malformed metadata",
			token:     createToken(t, "user id", []common.UniformResourceIdentifier{malformedMetadataUri}, int64(0), Service, jwtSecret),
			wantedErr: common.ErrInvalidToken,
		},
	}

	setup := setupAuthorizerTests(t, jwtSecret)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uris, err := setup.authorizer.GetAuthorizedResources(setup.testCtx, tt.token, tt.givenUris)
			assert.Nil(t, uris)
			assert.Equal(t, tt.wantedErr, errors.Cause(err))
		})
	}
}

func Test_verifyTokenType(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		wantErr   bool
	}{
		{
			tokenType: User,
		},
		{
			tokenType: Service,
		},
		{
			tokenType: "unknown type",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.tokenType), func(t *testing.T) {
			assert.Equal(t, tt.wantErr, verifyTokenType(tt.tokenType) != nil)
		})
	}
}

func TestAuthorizer_WithAuthMiddleware_should_call_HandleUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		prep func(*authorizerTestSetup)
	}{
		{
			name: "when token is empty",
			prep: func(setup *authorizerTestSetup) {
				setup.mockRouterResource.EXPECT().GetAuthToken(gomock.Any()).Return("").Times(1)
			},
		},
		{
			name: "when GetAuthorizedResources returns err",
			prep: func(setup *authorizerTestSetup) {
				setup.mockRouterResource.EXPECT().GetAuthToken(gomock.Any()).Return("invalid_token").Times(1)
				setup.mockRouterResource.EXPECT().GetResourcePath().Return("resource").Times(1)
			},
		},
		{
			name: "when GetAuthorizedResources returns empty array",
			prep: func(setup *authorizerTestSetup) {
				token := createToken(t, "test_token", nil, int64(10000), Service, "")
				setup.mockRouterResource.EXPECT().GetAuthToken(gomock.Any()).Return(token).Times(1)
				setup.mockRouterResource.EXPECT().GetResourcePath().Return("resource").Times(1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupAuthorizerTests(t, "")
			defer setup.ctrl.Finish()
			mockHandler := func(*gin.Context) {}
			tt.prep(&setup)

			setup.mockRouterResource.EXPECT().HandleUnauthorized(gomock.Any()).Times(1)

			wrappedHandler := setup.authorizer.WithAuthMiddleware(setup.mockRouterResource, mockHandler)

			wrappedHandler(setup.testCtx)
		})
	}

}

func TestAuthorizer_WithAuthMiddleware_should_call_handler_when_request_is_authorized(t *testing.T) {
	setup := setupAuthorizerTests(t, "")
	defer setup.ctrl.Finish()
	mockHandlerCalled := false
	mockHandler := func(*gin.Context) { mockHandlerCalled = true }
	testURI := createTestURI("resource")
	token := createToken(t, "test_token", []common.UniformResourceIdentifier{testURI}, int64(10000), Service, "")
	setup.mockRouterResource.EXPECT().GetAuthToken(gomock.Any()).Return(token).Times(1)
	setup.mockRouterResource.EXPECT().GetResourcePath().Return("resource").Times(1)

	wrappedHandler := setup.authorizer.WithAuthMiddleware(setup.mockRouterResource, mockHandler)

	wrappedHandler(setup.testCtx)

	assert.True(t, mockHandlerCalled)
}

func TestAuthorizer_GetUserIdFromToken__should_return_error(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantErr    error
		wantUserId primitive.ObjectID
	}{
		{
			name:    "when token is empty",
			token:   "",
			wantErr: common.ErrInvalidToken,
		},
		{
			name:    "when token type is not user",
			token:   createToken(t, "id", nil, int64(10000), Service, ""),
			wantErr: common.ErrInvalidTokenType,
		},
		{
			name:    "when user id is malformed",
			token:   createToken(t, "invalid id", nil, int64(10000), User, ""),
			wantErr: common.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupAuthorizerTests(t, "")
			defer setup.ctrl.Finish()

			userId, err := setup.authorizer.GetUserIdFromToken(tt.token)

			assert.Equal(t, tt.wantUserId, userId)
			assert.Equal(t, tt.wantErr, errors.Cause(err))
		})
	}
}

func TestAuthorizer_GetUserIdFromToken__should_return_correct_user_id(t *testing.T) {
	setup := setupAuthorizerTests(t, "")
	defer setup.ctrl.Finish()
	token := createToken(t, testUserId.Hex(), nil, int64(10000), User, "")

	userId, err := setup.authorizer.GetUserIdFromToken(token)

	assert.Equal(t, testUserId, userId)
	assert.NoError(t, err)
}

func TestAuthorizer_GetTokenTypeFromToken__should_return_error_when_token_is_invalid(t *testing.T) {
	setup := setupAuthorizerTests(t, "")
	defer setup.ctrl.Finish()

	tokenType, err := setup.authorizer.GetTokenTypeFromToken("invalid token")

	assert.Zero(t, tokenType)
	assert.Equal(t, common.ErrInvalidToken, errors.Cause(err))
}

func TestAuthorizer_GetTokenTypeFromToken__should_return_error_when_token_type_is_invalid(t *testing.T) {
	setup := setupAuthorizerTests(t, "")
	defer setup.ctrl.Finish()
	token := createToken(t, testUserId.Hex(), nil, int64(10000), "invalid token type", "")

	tokenType, err := setup.authorizer.GetTokenTypeFromToken(token)

	assert.Zero(t, tokenType)
	assert.Equal(t, common.ErrInvalidToken, errors.Cause(err))
}

func TestAuthorizer_GetTokenTypeFromToken__should_return_expected_token_type(t *testing.T) {
	setup := setupAuthorizerTests(t, "")
	defer setup.ctrl.Finish()
	token := createToken(t, testUserId.Hex(), nil, int64(10000), User, "")

	tokenType, err := setup.authorizer.GetTokenTypeFromToken(token)

	assert.Equal(t, User, tokenType)
	assert.NoError(t, err)
}

func createToken(t *testing.T, id string, allowedResources []common.UniformResourceIdentifier, timeToLive int64, tokenType TokenType, jwtSecret string) string {
	token := jwt.NewWithClaims(jwtSigningMethod, tokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        id,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() + timeToLive,
		},
		TokenType:        tokenType,
		AllowedResources: allowedResources,
	})

	tokenStr, err := token.SignedString([]byte(jwtSecret))
	assert.NoError(t, err)

	return tokenStr
}

func extractTokenClaims(t *testing.T, token string, jwtSecret string) tokenClaims {
	var claims tokenClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	assert.NoError(t, err)

	return claims
}

func TestAuthorizer_filterUrisWithInvalidMetadata__should_return_error_when_metadata_key_value_pair_is_invalid(t *testing.T) {
	setup := setupMetadataTests(t)
	defer setup.ctrl.Finish()

	uri, err := common.NewURIFromString(fmt.Sprintf("hs:hs_auth#%s=notadate", before))
	assert.NoError(t, err)

	_, err = setup.authorizer.filterUrisWithInvalidMetadata([]common.UniformResourceIdentifier{uri})
	assert.Error(t, err)
}

func TestAuthorizer_filterUrisWithInvalidMetadata__should_remove_uris_with_invalid_metadata(t *testing.T) {
	setup := setupMetadataTests(t)
	defer setup.ctrl.Finish()

	var testTime int64 = 1000
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(testTime, 0)).Times(1)

	uri1, err := common.NewURIFromString(fmt.Sprintf("hs:hs_auth#%s=%d", before, testTime+1))
	assert.NoError(t, err)
	uri2, err := common.NewURIFromString("hs:hs_auth")
	assert.NoError(t, err)

	filteredUris, err := setup.authorizer.filterUrisWithInvalidMetadata([]common.UniformResourceIdentifier{uri1, uri2})
	assert.NoError(t, err)

	assert.Equal(t, []common.UniformResourceIdentifier{uri2}, filteredUris)
}

func BenchmarkAuthorizer_GetAuthorizedResources_ServiceToken(b *testing.B) {
	b.StopTimer()

	jwtSecret := "test_secret"
	setup := setupAuthorizerBenchmarks(b, jwtSecret)
	defer setup.ctrl.Finish()

	testToken, _ := setup.authorizer.CreateServiceToken(setup.testCtx, testUserId,
		[]common.UniformResourceIdentifier{
			createTestURI("hs:hs_auth"),
			createTestURI("hs:hs_application"),
		}, testAuthTokenLifetime+setup.timeProvider.Now().Unix())

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		_, _ = setup.authorizer.GetAuthorizedResources(setup.testCtx, testToken, []common.UniformResourceIdentifier{createTestURI("hs:hs_application")})
	}
}

func BenchmarkAuthorizer_GetAuthorizedResources_UserToken(b *testing.B) {
	b.StopTimer()

	jwtSecret := "test_secret"
	setup := setupAuthorizerBenchmarks(b, jwtSecret)
	defer setup.ctrl.Finish()

	testToken, _ := setup.authorizer.CreateUserToken(testUserId, testAuthTokenLifetime+setup.timeProvider.Now().Unix())
	_, _ = setup.uRepo.InsertOne(context.Background(), &entities.User{
		ID:   testUserId,
		Role: "organiser",
	})

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		_, _ = setup.authorizer.GetAuthorizedResources(setup.testCtx, testToken, []common.UniformResourceIdentifier{createTestURI("hs:hs_application")})
	}
}
