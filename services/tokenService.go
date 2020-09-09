package services

import (
	"context"
	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenService interface {
	GenerateServiceTokenID() primitive.ObjectID
	CreateServiceToken(ctx context.Context, creatorId, jwt string) (*entities.ServiceToken, error)
	DeleteServiceToken(ctx context.Context, id string) error
}
