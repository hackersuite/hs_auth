package entities

import (
	"github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserField string

const (
	UserID            UserField = "_id"
	UserName          UserField = "name"
	UserEmail         UserField = "email"
	UserPassword      UserField = "password"
	UserEmailVerified UserField = "email_verified"
	UserEmailToken    UserField = "auth_level"
	UserAuthLevel     UserField = "team"
	UserTeam          UserField = "team"
)

// User is the struct to store registered users
type User struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
	Name          string             `json:"name" bson:"name" validate:"required"`
	Email         string             `json:"email" bson:"email" validate:"required,email"`
	Password      string             `json:"-" bson:"password" validate:"required,min=6,max=160"`
	EmailVerified bool               `json:"email_verified,omitempty" bson:"email_verified,omitempty"`
	EmailToken    string             `json:"email_token,omitempty" bson:"email_token,omitempty"`
	AuthLevel     common.AuthLevel   `json:"auth_level" bson:"auth_level" validate:"min=0,max=3"`
	Team          primitive.ObjectID `json:"team,omitempty" bson:"team,omitempty"`
}
