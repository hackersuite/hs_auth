package services

import (
	"context"
	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenService interface {
	AddServiceToken(ctx context.Context, tokenId primitive.ObjectID, creatorId, jwt string) (*entities.Token, error)
	DeleteServiceToken(ctx context.Context, id string) error
}
