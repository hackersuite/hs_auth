package multiplexers

import (
	"fmt"
	"github.com/pkg/errors"
	sendgridgo "github.com/sendgrid/sendgrid-go"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/services/multiplexers/types"
	v2 "github.com/unicsmcr/hs_auth/services/sendgrid/v2"
	smtplib "github.com/unicsmcr/hs_auth/services/smtp"
	"github.com/unicsmcr/hs_auth/utils"
)

func NewEmailServiceV2(cfg *config.AppConfig, env *environment.Env, smtpClient utils.SMTPClient,
	sendGridClient *sendgridgo.Client, userService services.UserService, authorizer authV2.Authorizer,
	timeProvider utils.TimeProvider) (services.EmailServiceV2, error) {
	switch cfg.Email.EmailDeliveryProvider {
	case types.SMTP:
		return smtplib.NewSMPTEmailService(cfg, env, smtpClient, userService, authorizer, timeProvider)
	case types.SendGrid:
		return v2.NewSendgridEmailServiceV2(cfg, env, sendGridClient, userService, authorizer, timeProvider)
	default:
		return nil, errors.New(fmt.Sprintf("email delivery provider %s is invalid", cfg.Email.EmailDeliveryProvider))
	}
}
