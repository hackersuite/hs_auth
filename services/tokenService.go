package services

import (
	"context"
	"github.com/unicsmcr/hs_auth/entities"
)

type TokenService interface {
	CreateServiceToken(ctx context.Context, creatorId, jwt string) (*entities.ServiceToken, error)
	DeleteServiceToken(ctx context.Context, id string) error
}
