package entities

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenField string

const (
	ServiceTokenID      TokenField = "_id"
	ServiceTokenJWT     TokenField = "jwt"
	ServiceTokenCreator TokenField = "creator"
)

// ServiceToken is the struct to store tokens
type ServiceToken struct {
	ID      primitive.ObjectID `bson:"_id"`
	JWT     string             `bson:"jwt" validate:"required"`
	Creator primitive.ObjectID `bson:"creator" validate:"required"`
}
