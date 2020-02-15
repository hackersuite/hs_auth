package utils

import (
	"os"

	"github.com/unicsmcr/hs_auth/environment"
	"go.uber.org/zap"
)

// NewLogger creates a new zap logger
func NewLogger() (*zap.Logger, error) {
	if os.Getenv(environment.Environment) == "prod" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}
