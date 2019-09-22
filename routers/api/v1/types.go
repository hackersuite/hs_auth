package v1

import (
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/utils/auth/common"
)

type getUsersRes struct {
	models.Response
	Users []entities.User `json:"users"`
}

type loginRes struct {
	models.Response
	Token string        `json:"token"`
	User  entities.User `json:"user,omitempty"`
}

type verifyRes struct {
	models.Response
	AuthLevel common.AuthLevel `json:"auth_level"`
	UserID    string           `json:"user_id"`
}

type getMeRes struct {
	models.Response
	User entities.User `json:"user,omitempty"`
}

type registerRes struct {
	models.Response
	User entities.User `json:"user,omitempty"`
}

type getTeamsRes struct {
	models.Response
	Teams []entities.Team `json:"teams"`
}

type createTeamRes struct {
	models.Response
	Team entities.Team `json:"team"`
}

type getTeamMembersRes struct {
	models.Response
	Users []entities.User `json:"users"`
}
