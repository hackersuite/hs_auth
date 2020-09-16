package repositories

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/x/bsonx"
)

// TokenRepository is the repository for Service Token objects
type TokenRepository struct {
	*mongo.Collection
}

const tokenCollection = "tokens"

// NewTokenRepository creates a new TokenRepository
func NewTokenRepository(db *mongo.Database) (*TokenRepository, error) {
	_, err := db.Collection("tokens").Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys: bsonx.Doc{{"creator", bsonx.Int32(1)}},
		},
	)

	if err != nil {
		return nil, err
	}

	return &TokenRepository{
		Collection: db.Collection(tokenCollection),
	}, nil
}
