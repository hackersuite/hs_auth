package repositories

import (
	"go.mongodb.org/mongo-driver/mongo"
)

// UserRepository is the repository for user objects
type UserRepository struct {
	*mongo.Collection
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *mongo.Database) UserRepository {
	return UserRepository{
		Collection: db.Collection("users"),
	}
}
