package auth

import (
	"fmt"
	"testing"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"github.com/dgrijalva/jwt-go"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/stretchr/testify/assert"

	"github.com/unicsmcr/hs_auth/entities"
)

func Test_NewJWT__should_throw_error_when_secret_empty(t *testing.T) {
	testUser := entities.User{}

	_, err := NewJWT(testUser, 100, []byte{})
	assert.Error(t, err)
}

func Test_NewJWT__should_return_correct_JWT(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)

	expectedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, common.AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:       testUser.ID.Hex(),
			IssuedAt: 100,
		},
		AuthLevel: 3,
	}).SignedString(testSecret)
	assert.NoError(t, err)

	actualToken, err := NewJWT(testUser, 100, testSecret)
	assert.NoError(t, err)

	assert.Equal(t, expectedToken, actualToken)
}

// TODO: outdated tests
func Test_IsValidJWT__should_return_correct_auth_claims_for_valid_JWT(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)

	token, err := NewJWT(testUser, 101, testSecret)
	fmt.Println(token)
	assert.NoError(t, err)

	claims := GetJWTClaims(token, testSecret)
	assert.NotNil(t, claims)

	assert.Equal(t, testUser.ID.Hex(), claims.Id)
	assert.Equal(t, testUser.AuthLevel, claims.AuthLevel)
}
func Test_IsValidJWT__should_return_nil_for_invalid_JWT(t *testing.T) {
	// token with an increased auth_level in claims (signed with the secret "test_secret")
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJqdGkiOiI1ZDZlYzA2Nzg4ODJhMTFhYmE0ZjMzODEiLCJpYXQiOjEwMSwiYXV0aF9sZXZlbCI6NH0HbBIrZiQxexzKrnU+GCM8VCs3ZwxaMg=="

	testSecret := []byte(`test_secret`)
	assert.Nil(t, GetJWTClaims(invalidToken, testSecret))
}

func Test_NewEmailToken__should_generate_token_of_required_length(t *testing.T) {
	token := NewEmailToken(32)
	assert.Equal(t, 32, len(token))
}

func Test_NewEmailToken__should_generate_a_random_token(t *testing.T) {
	tokens := map[string]bool{}

	for i := 0; i < 100; i++ {
		token := NewEmailToken(32)
		_, exists := tokens[token]
		assert.False(t, exists)
		tokens[token] = true
	}
}
