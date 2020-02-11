package entities

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TeamField string

const (
	TeamID      TeamField = "_id"
	TeamName    TeamField = "name"
	TeamCreator TeamField = "creator"
)

// Team is the struct to store teams
type Team struct {
	ID      primitive.ObjectID `json:"_id" bson:"_id"`
	Name    string             `json:"name"  bson:"name" validate:"required"`
	Creator primitive.ObjectID `json:"creator" bson:"creator" validate:"required"`
}
