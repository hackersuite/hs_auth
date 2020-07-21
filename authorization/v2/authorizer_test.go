package v2

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/environment"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"testing"
	"time"
)

func setupAuthorizerTests(t *testing.T, jwtSecret string) (Authorizer, *mock_utils.MockTimeProvider) {
	restore := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: jwtSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	restore()

	ctrl := gomock.NewController(t)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	return NewAuthorizer(mockTimeProvider, env), mockTimeProvider
}

func TestAuthorizer_CreateServiceToken(t *testing.T) {
	testOwner := "test_service"
	var testTTL int64 = 100
	testTimestamp := time.Now()
	testAllowedResources := []UniformResourceIdentifier{"test_resource"}

	tests := []struct {
		name   string
		checks func(claims TokenClaims)
	}{
		{
			name: "should use correct Id",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testOwner, claims.Id)
			},
		},
		{
			name: "should use correct IssuedAt",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testTimestamp.Unix(), claims.IssuedAt)
			},
		},
		{
			name: "should use correct ExpiresAt",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testTimestamp.Unix()+testTTL, claims.ExpiresAt)
			},
		},
		{
			name: "should use correct TokenType",
			checks: func(claims TokenClaims) {
				assert.Equal(t, service, claims.TokenType)
			},
		},
		{
			name: "should use correct AllowedResources",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testAllowedResources, claims.AllowedResources)
			},
		},
	}

	jwtSecret := "test_secret"
	authorizer, timeProvider := setupAuthorizerTests(t, jwtSecret)
	timeProvider.EXPECT().Now().Return(testTimestamp).Times(1)

	token, err := authorizer.CreateServiceToken(testOwner, testAllowedResources, testTTL)
	assert.NoError(t, err)

	claims := extractTokenClaims(t, token, jwtSecret)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checks(claims)
		})
	}
}

func TestAuthorizer_CreateUserToken(t *testing.T) {
	testUserId := primitive.NewObjectIDFromTimestamp(time.Now())
	var testTTL int64 = 100
	testTimestamp := time.Now()

	tests := []struct {
		name   string
		checks func(claims TokenClaims)
	}{
		{
			name: "should use correct Id",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testUserId.Hex(), claims.Id)
			},
		},
		{
			name: "should use correct IssuedAt",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testTimestamp.Unix(), claims.IssuedAt)
			},
		},
		{
			name: "should use correct ExpiresAt",
			checks: func(claims TokenClaims) {
				assert.Equal(t, testTimestamp.Unix()+testTTL, claims.ExpiresAt)
			},
		},
		{
			name: "should use correct TokenType",
			checks: func(claims TokenClaims) {
				assert.Equal(t, user, claims.TokenType)
			},
		},
	}

	jwtSecret := "test_secret"
	authorizer, timeProvider := setupAuthorizerTests(t, jwtSecret)
	timeProvider.EXPECT().Now().Return(testTimestamp).Times(1)

	token, err := authorizer.CreateUserToken(testUserId, testTTL)
	assert.NoError(t, err)

	claims := extractTokenClaims(t, token, jwtSecret)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checks(claims)
		})
	}
}

func TestAuthorizer_GetAuthorizedResources_should_return_correct_uris_when_token_is_valid(t *testing.T) {
	jwtSecret := "test_secret"
	authorizer, _ := setupAuthorizerTests(t, jwtSecret)
	token := createToken(t, "testuser", nil, int64(100), user, jwtSecret)

	uris := []UniformResourceIdentifier{"test"}

	returnedUris, err := authorizer.GetAuthorizedResources(token, uris)
	assert.NoError(t, err)

	assert.Equal(t, uris, returnedUris)
}

func TestAuthorizer_GetAuthorizedResources_should_return_err(t *testing.T) {
	jwtSecret := "jwtSecret"

	tests := []struct {
		name  string
		token string
		wantedErr error
	}{
		{
			name:  "when token is invalid",
			token: "invalid token",
			wantedErr: ErrInvalidToken,
		},
		{
			name:  "when token type is invalid",
			token: createToken(t, "user id", nil, int64(0), "unknown type", jwtSecret),
			wantedErr: ErrInvalidToken,
		},
		{
			name:  "when token is expired",
			token: createToken(t, "user id", nil, int64(-5), user, jwtSecret),
			wantedErr: ErrInvalidToken,
		},
	}

	authorizer, _ := setupAuthorizerTests(t, jwtSecret)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uris, err := authorizer.GetAuthorizedResources(tt.token, nil)
			assert.Nil(t, uris)
			assert.Equal(t, tt.wantedErr, errors.Cause(err))
		})
	}
}

func Test_verifyTokenType(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		wantErr bool
	}{
		{
			tokenType: user,
		},
		{
			tokenType: service,
		},
		{
			tokenType: "unknown type",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.tokenType), func(t *testing.T) {
			assert.Equal(t, tt.wantErr, verifyTokenType(tt.tokenType) != nil)
		})
	}
}

func createToken(t *testing.T, id string, allowedResources []UniformResourceIdentifier, timeToLive int64, tokenType TokenType, jwtSecret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
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

func extractTokenClaims(t *testing.T, token string, jwtSecret string) TokenClaims {
	var claims TokenClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	assert.NoError(t, err)

	return claims
}
