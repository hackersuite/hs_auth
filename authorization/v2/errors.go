package v2

import "errors"

var (
	// ErrInvalidToken is returned when the provided token is invalid or expired
	ErrInvalidToken = errors.New("invalid token")
)
