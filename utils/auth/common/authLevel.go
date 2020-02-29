package common

import (
	"errors"
)

// AuthLevel is a type for storing a users auth level
type AuthLevel int

const (
	// Unverified is the auth level that represents a user who has not yet verified their email
	Unverified AuthLevel = iota
	// Applicant is the auth level that represents a user who has not yet received and accepted an invite
	Applicant
	// Attendee is the auth level that represents a user who has received and accepted an invite
	Attendee
	// Volunteer is the auth level that represents a user who has access to volunteer features
	Volunteer
	// Organiser is the auth level that represents a user who has access to all features
	Organiser
)

var ErrUnknownAuthLevel = errors.New("auth level unknown")

// string representation of the auth levels.
// used when sending an AuthLevel in a JSON response
var stringAuthLevels = map[AuthLevel]string{
	Unverified: "\"unverified\"",
	Applicant: "\"applicant\"",
	Attendee:  "\"attendee\"",
	Volunteer: "\"volunteer\"",
	Organiser: "\"organiser\"",
}

func (al AuthLevel) MarshalJSON() ([]byte, error) {
	if lvl, ok := stringAuthLevels[al]; ok {
		return []byte(lvl), nil
	}
	return nil, ErrUnknownAuthLevel
}

func (al *AuthLevel) UnmarshalJSON(data []byte) error {
	for lvl, stringLvl := range stringAuthLevels {
		if stringLvl == string(data) {
			*al = lvl
			return nil
		}
	}
	return ErrUnknownAuthLevel
}