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
	// ErrEmailTaken is returned when trying to create a user with an email that is already in use
	ErrEmailTaken = errors.New("email is already taken")
	// ErrNameTaken is returned when trying to create a user or team with a name that is already in use
	ErrNameTaken = errors.New("name is already taken")
	// ErrInvalidToken is returned when the given auth token is invalid
	ErrInvalidToken = errors.New("invalid auth token")
	// ErrUserInTeam is returned when the given user is in a team but the method that
	// returns the error requires the user to not be in a team
	ErrUserInTeam = errors.New("user is already in a team")
	// ErrUserNotInTeam is returned when the given user is not in a team but the method that
	// returns the error requires the user to be in a team
	ErrUserNotInTeam = errors.New("user is not in a team")
)
