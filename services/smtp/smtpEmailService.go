package smtp

import (
	"bytes"
	"context"
	"fmt"
	"github.com/pkg/errors"
	authV2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"html/template"
	"net/smtp"
)

var (
	passwordResetEmailTemplatePath = "templates/emails/passwordReset_email.gohtml"
	emailVerifyEmailTemplatePath   = "templates/emails/emailVerify_email.gohtml"
	htmlEmailTemplateStr           = `From: %s <%s>
To: %s <%s>
Subject: %s
Mime-Version: 1.0;
Content-Type: text/html; charset="UTF-8";
Content-Transfer-Encoding: 8bit;

%s
`
)

type emailBodyTemplateDataModel struct {
	EventName  string
	Link       string
	SenderName string
}

type smtpEmailService struct {
	cfg          *config.AppConfig
	env          *environment.Env
	client       utils.SMTPClient
	userService  services.UserService
	authorizer   authV2.Authorizer
	timeProvider utils.TimeProvider

	smtpAuth                       smtp.Auth
	passwordResetEmailBodyTemplate *template.Template
	emailVerifyEmailBodyTemplate   *template.Template
}

func NewSMPTEmailService(cfg *config.AppConfig, env *environment.Env, client utils.SMTPClient,
	userService services.UserService, authorizer authV2.Authorizer,
	timeProvider utils.TimeProvider) (services.EmailServiceV2, error) {
	passwordResetEmailTemplate, err := utils.LoadTemplate("password reset", passwordResetEmailTemplatePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load password reset template")
	}

	emailVerifyEmailTemplate, err := utils.LoadTemplate("email verify", emailVerifyEmailTemplatePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load email verify template")
	}

	return &smtpEmailService{
		cfg:                            cfg,
		env:                            env,
		client:                         client,
		userService:                    userService,
		passwordResetEmailBodyTemplate: passwordResetEmailTemplate,
		emailVerifyEmailBodyTemplate:   emailVerifyEmailTemplate,
		authorizer:                     authorizer,
		timeProvider:                   timeProvider,
		smtpAuth: smtp.PlainAuth("", env.Get(environment.SMTPUsername),
			env.Get(environment.SMTPPassword), env.Get(environment.SMTPHost)),
	}, nil
}

func (s *smtpEmailService) SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error {
	message := fmt.Sprintf(htmlEmailTemplateStr, senderName, senderEmail, recipientName, recipientEmail, subject, htmlBody)

	err := s.client.SendEmail(fmt.Sprintf("%s:%s", s.env.Get(environment.SMTPHost), s.env.Get(environment.SMTPPort)),
		s.smtpAuth, senderEmail, []string{recipientEmail}, []byte(message))
	if err != nil {
		return errors.Wrap(err, "could not send email")
	}

	return nil
}
func (s *smtpEmailService) SendEmailVerificationEmail(ctx context.Context, user entities.User, emailVerificationResources common.UniformResourceIdentifiers) error {
	// TODO: the emails should use tokens of type "email" (https://github.com/unicsmcr/hs_auth/issues/121)
	emailToken, err := s.authorizer.CreateServiceToken(ctx, user.ID,
		emailVerificationResources, s.timeProvider.Now().Unix()+s.cfg.Email.TokenLifetime)
	if err != nil {
		return errors.Wrap(err, "could not create auth token for email")
	}

	verificationURL := fmt.Sprintf("http://%s/verifyemail?token=%s&userId=%s", s.cfg.AppURL, emailToken, user.ID.Hex())

	var contentBuff bytes.Buffer
	err = s.emailVerifyEmailBodyTemplate.Execute(&contentBuff, emailBodyTemplateDataModel{
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
		"",
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}

func (s *smtpEmailService) SendPasswordResetEmail(ctx context.Context, user entities.User, passwordResetResources common.UniformResourceIdentifiers) error {
	// TODO: the emails should use tokens of type "email" (https://github.com/unicsmcr/hs_auth/issues/1210
	emailToken, err := s.authorizer.CreateServiceToken(ctx, user.ID,
		passwordResetResources, s.timeProvider.Now().Unix()+s.cfg.Email.TokenLifetime)
	if err != nil {
		return errors.Wrap(err, "could not create auth token for email")
	}

	resetURL := fmt.Sprintf("http://%s/resetpwd?token=%s&userId=%s", s.cfg.AppURL, emailToken, user.ID.Hex())

	var contentBuff bytes.Buffer
	err = s.passwordResetEmailBodyTemplate.Execute(&contentBuff, emailBodyTemplateDataModel{
		Link:       resetURL,
		SenderName: s.cfg.Email.NoreplyEmailName,
	})
	if err != nil {
		return errors.Wrap(err, "could not construct email")
	}

	return s.SendEmail(
		s.cfg.Email.PasswordResetEmailSubj,
		contentBuff.String(),
		"",
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}
