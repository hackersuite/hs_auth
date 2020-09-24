package v2

import (
	"context"
	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"html/template"
	"net/http"
)

var (
	passwordResetEmailTemplatePath = "templates/emails/passwordReset_email.gohtml"
	emailVerifyEmailTemplatePath   = "templates/emails/emailVerify_email.gohtml"
)

type sendgridEmailService struct {
	*sendgrid.Client
	cfg         *config.AppConfig
	env         *environment.Env
	userService services.UserService
	authorizer  authV2.Authorizer

	passwordResetEmailTemplate *template.Template
	emailVerifyEmailTemplate   *template.Template
}

func NewSendgridEmailServiceV2(cfg *config.AppConfig, env *environment.Env,
	client *sendgrid.Client, userService services.UserService, authorizer authV2.Authorizer) (services.EmailServiceV2, error) {
	passwordResetEmailTemplate, err := utils.LoadTemplate("password reset", passwordResetEmailTemplatePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load password reset template")
	}

	emailVerifyEmailTemplate, err := utils.LoadTemplate("email verify", emailVerifyEmailTemplatePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load email verify template")
	}

	return &sendgridEmailService{
		Client:                     client,
		cfg:                        cfg,
		env:                        env,
		userService:                userService,
		passwordResetEmailTemplate: passwordResetEmailTemplate,
		emailVerifyEmailTemplate:   emailVerifyEmailTemplate,
		authorizer:                 authorizer,
	}, nil
}

func (s *sendgridEmailService) SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error {
	from := mail.NewEmail(senderName, senderEmail)
	to := mail.NewEmail(recipientName, recipientEmail)
	message := mail.NewSingleEmail(from, subject, to, plainTextBody, htmlBody)
	response, err := s.Send(message)

	if err != nil {
		return errors.Wrap(err, "could not send email request to SendGrid")
	}

	if response.StatusCode != http.StatusAccepted {
		return services.ErrSendgridRejectedRequest
	}

	return nil
}
func (s *sendgridEmailService) SendEmailVerificationEmail(user entities.User, emailVerificationResourcePath string) error {
	panic("not implemented")
}
func (s *sendgridEmailService) SendEmailVerificationEmailForUserWithEmail(ctx context.Context, email string, emailVerificationResourcePath string) error {
	panic("not implemented")
}
func (s *sendgridEmailService) SendPasswordResetEmail(user entities.User, passwordResetResourcePath string) error {
	panic("not implemented")
}
func (s *sendgridEmailService) SendPasswordResetEmailForUserWithEmail(ctx context.Context, email string, passwordResetResourcePath string) error {
	panic("not implemented")
}
