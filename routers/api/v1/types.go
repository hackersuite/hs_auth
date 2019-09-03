package v1

import (
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
)

type getUsersRes struct {
	models.Response
	Users []entities.User `json:"users"`
}

type loginRes struct {
	models.Response
	Token string `json:"token"`
}

type verifyRes struct {
	models.Response
}
