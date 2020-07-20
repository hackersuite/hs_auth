package utils

import "time"

// Helper interface to make mocking time.Now() easier
type TimeProvider interface {
	Now() time.Time
}

func NewTimeProvider() TimeProvider {
	return &timeProvider{}
}

type timeProvider struct{}

func (*timeProvider) Now() time.Time {
	return time.Now()
}
