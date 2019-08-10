package common

// AuthLevel is a type for storing a users auth level
type AuthLevel int

const (
	// Applicant is the auth level that represents a user who has not yet received and accepted an invite
	Applicant AuthLevel = iota
	// Attendee is the auth level that represents a user who has received and accepted an invite
	Attendee
	// Volunteer is the auth level that represents a user who has access to volunteer features
	Volunteer
	// Organizer is the auth level that represents a user who has access to all features
	Organizer
)
