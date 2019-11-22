package sendgrid

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"github.com/unicsmcr/hs_auth/utils"

	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

var (
	passwordResetEmailTemplatePath = "templates/emails/passwordReset_email.gohtml"
	emailVerifyEmailTemplatePath   = "templates/emails/emailVerify_email.gohtml"
)

type sendgridEmailService struct {
	*sendgrid.Client
	logger      *zap.Logger
	cfg         *config.AppConfig
	userService services.UserServiceV2

	passwordResetEmailTemplate *template.Template
	emailVerifyEmailTemplate   *template.Template
}

type emailTemplateDataModel struct {
	Link       string
	SenderName string
}

func NewSendgridEmailService(logger *zap.Logger, cfg *config.AppConfig, client *sendgrid.Client, userService services.UserServiceV2) (services.EmailServiceV2, error) {
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
		logger:                     logger,
		cfg:                        cfg,
		userService:                userService,
		passwordResetEmailTemplate: passwordResetEmailTemplate,
		emailVerifyEmailTemplate:   emailVerifyEmailTemplate,
	}, nil
}

func (s *sendgridEmailService) SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error {
	from := mail.NewEmail(senderName, senderEmail)
	to := mail.NewEmail(recipientName, recipientEmail)
	message := mail.NewSingleEmail(from, subject, to, plainTextBody, htmlBody)
	response, err := s.Send(message)

	if err != nil {
		s.logger.Error("could not issue email request",
			zap.String("subject", subject),
			zap.String("recipient", recipientEmail),
			zap.String("sender", senderEmail),
			zap.Error(err))
		return errors.Wrap(err, "could not send email request to SendGrid")
	}

	if response.StatusCode != http.StatusAccepted {
		s.logger.Error("email request was rejected by Sendgrid",
			zap.String("subject", subject),
			zap.String("recipient", recipientEmail),
			zap.String("sender", senderEmail),
			zap.Int("response status code", response.StatusCode),
			zap.String("response body", response.Body))
		return services.ErrSendgridRejectedRequest
	}

	s.logger.Info("email request sent successfully",
		zap.String("subject", subject),
		zap.String("recipient", recipientEmail),
		zap.String("sender", senderEmail))
	return nil
}
func (s *sendgridEmailService) SendEmailVerificationEmail(user entities.User) error {
	// TODO: make email token
	emailToken := ""

	verificationURL := fmt.Sprintf("http://%s/verifyemail?token=%s", s.cfg.AppURL, emailToken)

	var contentBuff bytes.Buffer
	err := s.passwordResetEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
		Link:       verificationURL,
		SenderName: s.cfg.Email.NoreplyEmailName,
	})
	if err != nil {
		return errors.Wrap(err, "could not construct email")
	}

	return s.SendEmail(
		s.cfg.Email.EmailVerficationEmailSubj,
		contentBuff.String(),
		contentBuff.String(),
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}
func (s *sendgridEmailService) SendEmailVerificationEmailForUserWithEmail(ctx context.Context, email string) error {
	user, err := s.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		return err
	}

	return s.SendEmailVerificationEmail(*user)
}
func (s *sendgridEmailService) SendPasswordResetEmail(user entities.User) error {
	// TODO: make email token
	emailToken := ""

	resetURL := fmt.Sprintf("http://%s/resetpwd?email=%s&token=%s", s.cfg.AppURL, user.Email, emailToken)

	var contentBuff bytes.Buffer
	err := s.passwordResetEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
		Link:       resetURL,
		SenderName: s.cfg.Email.NoreplyEmailName,
	})
	if err != nil {
		return errors.Wrap(err, "could not construct email")
	}

	return s.SendEmail(
		s.cfg.Email.PasswordResetEmailSubj,
		contentBuff.String(),
		contentBuff.String(),
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}
func (s *sendgridEmailService) SendPasswordResetEmailForUserWithEmail(ctx context.Context, email string) error {
	user, err := s.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		return err
	}

	return s.SendPasswordResetEmail(*user)
}
