package entities

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenField string

const (
	TokenID      TokenField = "_id"
	TokenJWT     TokenField = "jwt"
	TokenCreator TokenField = "creator"
)

// Token is the struct to store tokens
type Token struct {
	ID      primitive.ObjectID `json:"_id" bson:"_id"`
	JWT     string             `json:"jwt"  bson:"jwt" validate:"required"`
	Creator primitive.ObjectID `json:"creator"  bson:"creator" validate:"required"`
}
