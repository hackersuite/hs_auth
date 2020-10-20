package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

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
