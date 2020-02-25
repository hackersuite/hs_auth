package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

func Test_NewJWT__should_throw_error_when_secret_empty(t *testing.T) {
	testUser := entities.User{}

	_, err := NewJWT(testUser, 100, 0, Auth, []byte{})
	assert.Error(t, err)
}

func Test_NewJWT__should_return_correct_JWT(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)

	expectedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		StandardClaims: jwt.StandardClaims{
			Id:        testUser.ID.Hex(),
			IssuedAt:  100,
			ExpiresAt: 300,
		},
		AuthLevel: 3,
		TokenType: Auth,
	}).SignedString(testSecret)
	assert.NoError(t, err)

	actualToken, err := NewJWT(testUser, 100, 200, Auth, testSecret)
	assert.NoError(t, err)

	assert.Equal(t, expectedToken, actualToken)
}

func Test_GetJWTClaims__should_return_nil_for_expired_token(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)
	token, err := NewJWT(testUser, time.Now().Unix(), -100, Email, testSecret)
	assert.NoError(t, err)

	claims := GetJWTClaims(token, testSecret)
	assert.Nil(t, claims)
}

func Test_GetJWTClaims__should_return_correct_auth_claims_for_valid_JWT(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)

	token, err := NewJWT(testUser, time.Now().Unix(), 10000, Email, testSecret)
	assert.NoError(t, err)

	claims := GetJWTClaims(token, testSecret)
	assert.NotNil(t, claims)

	assert.Equal(t, testUser.ID.Hex(), claims.Id)
	assert.Equal(t, testUser.AuthLevel, claims.AuthLevel)
	assert.Equal(t, Email, claims.TokenType)
}
func Test_GetJWTClaims__should_return_nil_for_invalid_JWT(t *testing.T) {
	// token with an increased auth_level in claims (signed with the secret "test_secret")
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJqdGkiOiI1ZDZlYzA2Nzg4ODJhMTFhYmE0ZjMzODEiLCJpYXQiOjEwMSwiYXV0aF9sZXZlbCI6NH0HbBIrZiQxexzKrnU+GCM8VCs3ZwxaMg=="

	testSecret := []byte(`test_secret`)
	assert.Nil(t, GetJWTClaims(invalidToken, testSecret))
}

func Test_GetHashForPassword__should_return_expected_hash(t *testing.T) {
	hash, err := GetHashForPassword("test password")
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("test password"))
	assert.NoError(t, err)
}

func Test_CompareHashAndPassword__should_return_nil_for_valid_hash_and_password_combination(t *testing.T) {
	password := "test password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	assert.NoError(t, CompareHashAndPassword(string(hash), password))
}

func Test_CompareHashAndPassword__should_return_nil_for_invalid_hash_and_password_combination(t *testing.T) {
	password := "test password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	password += "invalid"

	assert.Error(t, CompareHashAndPassword(string(hash), password))
}

func Test_ExtractClaimsFromCtx__should_return_nil_when_ctx_doesnt_have_auth_claims(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())

	claims := ExtractClaimsFromCtx(testCtx)
	assert.Nil(t, claims)
}

func Test_ExtractClaimsFromCtx__should_return_nil_when_claims_in_ctx_are_of_different_type(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())

	testCtx.Set(AuthTokenKeyInCtx, true)

	claims := ExtractClaimsFromCtx(testCtx)
	assert.Nil(t, claims)
}

func Test_ExtractClaimsFromCtx__should_return_correct_claims(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	expectedClaims := &Claims{
		StandardClaims: jwt.StandardClaims{
			Id: "test id",
		},
	}

	testCtx.Set(AuthTokenKeyInCtx, expectedClaims)

	claims := ExtractClaimsFromCtx(testCtx)
	assert.Equal(t, expectedClaims, claims)
}

func Test_AuthLevelVerifierFactory__should_return_middleware(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		givenAuthLevel common.AuthLevel
		wantNextCalled bool
		wantAuthLevel  common.AuthLevel
	}{
		{
			name:  "that calls failCallback when given token is invalid",
			token: "not valid token",
		},
		{
			name:  "that calls failCallback when given token is an email token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDdhOTM4NmU0OGZhMTY1NTZjNTY0MTEiLCJpYXQiOjEwMCwiYXV0aF9sZXZlbCI6MywidG9rZW5fdHlwZSI6ImVtYWlsIn0.Hsi2STFazVwcQ73sG8BKg3dmIx_XnijFoJx6BNYuGPc",
		},
		{
			name:           "that calls failCallback when auth level is too low",
			givenAuthLevel: 0,
			wantAuthLevel:  3,
		},
		{
			name:           "that calls next handler when auth level is equal to required",
			givenAuthLevel: 3,
			wantAuthLevel:  3,
			wantNextCalled: true,
		},
		{
			name:           "that calls next handler when auth level is above required",
			givenAuthLevel: 3,
			wantAuthLevel:  2,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.token
			if token == "" {
				testUser := entities.User{
					AuthLevel: tt.givenAuthLevel,
					ID:        primitive.NewObjectID(),
				}
				var err error
				token, err = NewJWT(testUser, time.Now().Unix(), 10000000, Auth, []byte("testsecret"))
				assert.NoError(t, err)
			}

			failures := 0
			levelVerifier := AuthLevelVerifierFactory(tt.wantAuthLevel, func(*gin.Context) string {
				return token
			}, []byte("testsecret"), func(*gin.Context) {
				failures++
			})

			w := httptest.NewRecorder()
			testCtx, _ := gin.CreateTestContext(w)

			levelVerifier(testCtx)

			claims := ExtractClaimsFromCtx(testCtx)
			if tt.wantNextCalled {
				assert.Zero(t, failures)
				assert.NotNil(t, claims)
			} else {
				assert.Equal(t, 1, failures)
				assert.Nil(t, claims)
			}
		})
	}
}
