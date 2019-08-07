package utils

import (
	"os"

	"go.uber.org/zap"
)

func NewLogger() (*zap.Logger, error) {
	if os.Getenv("ENVIRONMENT") == "prod" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}
