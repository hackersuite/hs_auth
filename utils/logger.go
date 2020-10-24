package utils

import (
	"os"

	"github.com/unicsmcr/hs_auth/environment"
	"go.uber.org/zap"
)

const logFile = "app.log"

// NewLogger creates a new zap logger
func NewLogger() (*zap.Logger, error) {
	if os.Getenv(environment.Environment) == "prod" {
		cfg := zap.NewProductionConfig()
		cfg.OutputPaths = []string{logFile, os.Stdout.Name()}
		return cfg.Build()
	}
	return zap.NewDevelopment()
}
