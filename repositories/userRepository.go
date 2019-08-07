package repositories

import (
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	*mongo.Collection
}

func NewUserRepository(db *mongo.Database) UserRepository {
	return UserRepository{
		Collection: db.Collection("user"),
	}
}
