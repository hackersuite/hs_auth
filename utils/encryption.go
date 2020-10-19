package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// GetHashForPassword generates a hash for the given password with the given salt
func GetHashForPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CompareHashAndPassword compares the hash to the password.
// If they both represent the same string, returns nill.
// Returns an error otherwise
func CompareHashAndPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
