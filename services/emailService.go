package services

import (
	"fmt"
	"net/http"

	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"go.uber.org/zap"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// EmailService is used to send out emails
type EmailService interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error
	SendEmailVerificationEmail(user entities.User, emailToken string) error
	SendPasswordResetEmail(user entities.User, emailToken string) error
}

type emailService struct {
	*sendgrid.Client
	logger *zap.Logger
	cfg    *config.AppConfig
	env    *environment.Env
}

// NewEmailClient creates a new email client that uses Sendgrid
func NewEmailClient(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env) EmailService {
	sendgridClient := sendgrid.NewSendClient(env.Get(environment.SendgridAPIKey))

	return &emailService{
		Client: sendgridClient,
		logger: logger,
		cfg:    cfg,
		env:    env,
	}
}

func (s *emailService) SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error {
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
		return err
	}

	if response.StatusCode != http.StatusAccepted {
		s.logger.Error("email request was rejected by Sendgrid",
			zap.String("subject", subject),
			zap.String("recipient", recipientEmail),
			zap.String("sender", senderEmail),
			zap.Int("response status code", response.StatusCode),
			zap.String("response body", response.Body))
		return ErrSendgridRejectedRequest
	}

	s.logger.Info("email request sent successfully",
		zap.String("subject", subject),
		zap.String("recipient", recipientEmail),
		zap.String("sender", senderEmail))
	return nil
}

func (s *emailService) SendEmailVerificationEmail(user entities.User, emailToken string) error {
	verificationURL := fmt.Sprintf("http://%s/api/v1/users/email/verify?token=%s", s.cfg.AppURL, emailToken)

	return s.SendEmail(
		s.cfg.Email.EmailVerficationEmailSubj,
		verificationURL,
		verificationURL,
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}

func (s *emailService) SendPasswordResetEmail(user entities.User, emailToken string) error {
	return s.SendEmail(
		s.cfg.Email.PasswordResetEmailSubj,
		emailToken,
		emailToken,
		s.cfg.Email.NoreplyEmailName,
		s.cfg.Email.NoreplyEmailAddr,
		user.Name,
		user.Email)
}
