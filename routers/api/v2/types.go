package v2

import (
	"github.com/unicsmcr/hs_auth/authorization/v2"
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

type getAuthorizedResourcesRes struct {
	AuthorizedUris []v2.UniformResourceIdentifier `json:"authorizedUris"`
}
