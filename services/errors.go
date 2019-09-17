package services

import "errors"

var (
	// ErrInvalidID is the error returned by services when
	// the id provided in the call to the service is invalid
	ErrInvalidID = errors.New("id was invalid or not provided")
	// ErrNotFound is the error returned by services when
	// the requested object could not be found
	ErrNotFound = errors.New("requested object could not be found")
	// ErrSendgridRejectedRequest is the error returned by EmailService
	// when Sendgrid rejects an email request
	ErrSendgridRejectedRequest = errors.New("email request was rejected by Sendgrid")
)
