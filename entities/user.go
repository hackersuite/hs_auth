package entities

import (
	"github.com/unicsmcr/hs_auth/utils"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User is the struct to store registered users
type User struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
	Name          string             `json:"name" bson:"name" validate:"required"`
	Email         string             `json:"email" bson:"email" validate:"required,email"`
	Password      string             `json:"password" bson:"password" validate:"required,min=6,max=50"`
	EmailVerified bool               `json:"email_verified,omitempty" bson:"email_verified,omitempty"`
	AuthLevel     utils.AuthLevel    `json:"auth_level,omitempty" bson:"auth_level,omitempty" validate:"min=0"`
	Team          primitive.ObjectID `json:"team,omitempty" bson:"team,omitempty"`
}
