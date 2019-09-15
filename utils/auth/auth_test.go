package auth

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/stretchr/testify/assert"

	"github.com/unicsmcr/hs_auth/entities"
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
			Id:       testUser.ID.Hex(),
			IssuedAt: 100,
		},
		AuthLevel: 3,
		TokenType: Auth,
	}).SignedString(testSecret)
	assert.NoError(t, err)

	actualToken, err := NewJWT(testUser, 100, 0, Auth, testSecret)
	assert.NoError(t, err)

	assert.Equal(t, expectedToken, actualToken)
}

// TODO: outdated tests
func Test_GetJWTClaims__should_return_correct_auth_claims_for_valid_JWT(t *testing.T) {
	testUser := entities.User{
		ID:        primitive.NewObjectID(),
		AuthLevel: 3,
	}
	testSecret := []byte(`test_secret`)

	token, err := NewJWT(testUser, 101, 0, Email, testSecret)
	fmt.Println(token)
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
