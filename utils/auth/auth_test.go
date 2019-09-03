package auth

import (
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
			Id:       testUser.ID.String(),
			IssuedAt: 100,
		},
		AuthLevel: 3,
	}).SignedString(testSecret)
	assert.NoError(t, err)

	actualToken, err := NewJWT(testUser, 100, testSecret)
	assert.NoError(t, err)

	assert.Equal(t, expectedToken, actualToken)
}
