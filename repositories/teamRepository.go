package repositories

import (
	"go.mongodb.org/mongo-driver/mongo"
)

// TeamRepository is the repository for Team objects
type TeamRepository struct {
	*mongo.Collection
}

// NewTeamRepository creates a new TeamRepository
func NewTeamRepository(db *mongo.Database) TeamRepository {
	return TeamRepository{
		Collection: db.Collection("teams"),
	}
}
