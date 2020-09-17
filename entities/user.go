package entities

import (
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	v1 "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserField string

const (
	UserID                 UserField = "_id"
	UserName               UserField = "name"
	UserEmail              UserField = "email"
	UserPassword           UserField = "password"
	UserAuthLevel          UserField = "auth_level"
	UserTeam               UserField = "team"
	UserSpecialPermissions UserField = "special_permissions"
)

// User is the struct to store registered users
type User struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
	Name          string             `json:"name" bson:"name" validate:"required"`
	Email         string             `json:"email" bson:"email" validate:"required,email"`
	Password      string             `json:"-" bson:"password" validate:"required,min=6,max=160"`
	EmailVerified bool               `json:"email_verified,omitempty" bson:"email_verified,omitempty"`
	AuthLevel     v1.AuthLevel       `json:"auth_level" bson:"auth_level" validate:"min=0,max=4"`
	// TODO: omit team from JSON when team is primitive.NilObjectID
	Team               primitive.ObjectID                `json:"team,omitempty" bson:"team,omitempty"`
	SpecialPermissions common.UniformResourceIdentifiers `json:"special_permissions" bson:"special_permissions,omitempty" validate:"required"`
}
