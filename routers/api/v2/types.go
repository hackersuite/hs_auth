package v2

import (
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/entities"
)

type loginRes struct {
	Token string `json:"token"`
}

type serviceTokenRes struct {
	Token string `json:"token"`
}

type getUsersRes struct {
	Users []entities.User `json:"users"`
}

type getUserRes struct {
	User entities.User `json:"user"`
}

type getAuthorizedResourcesRes struct {
	AuthorizedUris []common.UniformResourceIdentifier `json:"authorizedUris"`
}

type getTeamsRes struct {
	Teams []entities.Team `json:"teams"`
}

type getTeamRes struct {
	Team entities.Team `json:"team"`
}

type createTeamRes struct {
	Team entities.Team `json:"team"`
}
