package utils

import (
	"github.com/sendgrid/sendgrid-go"
	"github.com/unicsmcr/hs_auth/environment"
)

func NewSendgridClient(env *environment.Env) *sendgrid.Client {
	return sendgrid.NewSendClient(env.Get(environment.SendgridAPIKey))
}
