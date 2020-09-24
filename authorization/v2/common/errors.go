package common

import "errors"

var (
	// ErrInvalidToken is returned when the provided token is invalid or expired
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidURI is returned when the provided URI string is invalid or cannot be parsed
	ErrInvalidURI = errors.New("invalid URI string")
	// ErrInvalidTokenType is returned when the type of the token is invalid for the requested operation
	ErrInvalidTokenType = errors.New("invalid token type for requested operation")
	// ErrPersistToken is returned when the token could not be persisted
	ErrPersistToken = errors.New("token could not be persisted")
	// ErrUnknownRole is returned when the provided role is invalid
	ErrUnknownRole = errors.New("unknown role")
)
