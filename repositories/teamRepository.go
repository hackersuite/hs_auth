package repositories

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"
)

// TeamRepository is the repository for Team objects
type TeamRepository struct {
	*mongo.Collection
}

// NewTeamRepository creates a new TeamRepository
func NewTeamRepository(db *mongo.Database) (TeamRepository, error) {
	_, err := db.Collection("teams").Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bsonx.Doc{{"name", bsonx.Int32(1)}},
			Options: options.Index().SetUnique(true),
		},
	)

	if err != nil {
		return TeamRepository{}, err
	}

	return TeamRepository{
		Collection: db.Collection("teams"),
	}, nil
}
