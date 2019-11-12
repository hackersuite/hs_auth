package entities

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Team is the struct to store teams
type Team struct {
	ID      primitive.ObjectID `json:"_id" bson:"_id"`
	Name    string             `json:"name"  bson:"name" validate:"required"`
	TableNo int                `json:"table_no" bson:"table_no"`
	Creator primitive.ObjectID `json:"creator" bson:"creator" validate:"required"`
}
