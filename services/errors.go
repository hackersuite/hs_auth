package services

import "errors"

var (
	// ErrInvalidID is the error returned by services when
	// the id provided in the call to the service is invalid
	ErrInvalidID = errors.New("invalid id")
	// ErrNotFound is the error returned by services when
	// the requested object could not be found
	ErrNotFound = errors.New("requested object not found")
	// ErrSendgridRejectedRequest is the error returned by EmailService
	// when Sendgrid rejects an email request
	ErrSendgridRejectedRequest = errors.New("email request rejected by Sendgrid")

	// User service errors
	ErrEmailTaken   = errors.New("email is already taken")
	ErrInvalidToken = errors.New("invalid auth token")
)
