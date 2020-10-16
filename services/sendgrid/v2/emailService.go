package v2

import (
	"bytes"
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
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

type emailTemplateDataModel struct {
	EventName  string
	Link       string
	SenderName string
}

type sendgridEmailService struct {
	*sendgrid.Client
	cfg          *config.AppConfig
	env          *environment.Env
	userService  services.UserService
	authorizer   authV2.Authorizer
	timeProvider utils.TimeProvider

	passwordResetEmailTemplate *template.Template
	emailVerifyEmailTemplate   *template.Template
}

func NewSendgridEmailServiceV2(cfg *config.AppConfig, env *environment.Env,
	client *sendgrid.Client, userService services.UserService, authorizer authV2.Authorizer,
	timeProvider utils.TimeProvider) (services.EmailServiceV2, error) {
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
		timeProvider:               timeProvider,
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
func (s *sendgridEmailService) SendEmailVerificationEmail(ctx context.Context, user entities.User, emailVerificationResources common.UniformResourceIdentifiers) error {
	// TODO: the emails should use tokens of type "email" (https://github.com/unicsmcr/hs_auth/issues/121)
	emailToken, err := s.authorizer.CreateServiceToken(ctx, user.ID,
		emailVerificationResources, s.timeProvider.Now().Unix()+s.cfg.Email.TokenLifetime)
	if err != nil {
		return errors.Wrap(err, "could not create auth token for email")
	}

	verificationURL := fmt.Sprintf("http://%s/verifyemail?token=%s", s.cfg.AppURL, emailToken)

	var contentBuff bytes.Buffer
	err = s.emailVerifyEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
		EventName:  s.cfg.Name,
		Link:       verificationURL,
		SenderName: s.cfg.Email.NoreplyEmailName,
	})
	if err != nil {
		return errors.Wrap(err, "could not construct email")
	}

	return s.SendEmail(
		s.cfg.Email.EmailVerificationEmailSubj,
		contentBuff.String(),
		// TODO: plaintext should not be the same as HTML (https://github.com/unicsmcr/hs_auth/issues/120)
		contentBuff.String(),
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}

func (s *sendgridEmailService) SendPasswordResetEmail(ctx context.Context, user entities.User, passwordResetResources common.UniformResourceIdentifiers) error {
	// TODO: the emails should use tokens of type "email" (https://github.com/unicsmcr/hs_auth/issues/1210
	emailToken, err := s.authorizer.CreateServiceToken(ctx, user.ID,
		passwordResetResources, s.timeProvider.Now().Unix()+s.cfg.Email.TokenLifetime)
	if err != nil {
		return errors.Wrap(err, "could not create auth token for email")
	}

	resetURL := fmt.Sprintf("http://%s/resetpwd?token=%s&userId=%s", s.cfg.AppURL, emailToken, user.ID.Hex())

	var contentBuff bytes.Buffer
	err = s.passwordResetEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
		Link:       resetURL,
		SenderName: s.cfg.Email.NoreplyEmailName,
	})
	if err != nil {
		return errors.Wrap(err, "could not construct email")
	}

	return s.SendEmail(
		s.cfg.Email.PasswordResetEmailSubj,
		contentBuff.String(),
		// TODO: plaintext should not be the same as HTML (https://github.com/unicsmcr/hs_auth/issues/120)
		contentBuff.String(),
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}
