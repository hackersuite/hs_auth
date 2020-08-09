package v2

import "errors"

var (
	// ErrInvalidToken is returned when the provided token is invalid or expired
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidURI is returned when the provided URI string is invalid or cannot be parsed
	ErrInvalidURI = errors.New("invalid URI string")
)
