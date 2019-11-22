package services

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"go.uber.org/zap"
)

// EmailService is used to send out emails
type EmailService interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error
	SendEmailVerificationEmail(user entities.User, emailToken string) error
	SendPasswordResetEmail(user entities.User, emailToken string) error
}

type EmailServiceV2 interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error

	SendEmailVerificationEmail(user entities.User) error
	SendEmailVerificationEmailForUserWithEmail(ctx context.Context, email string) error

	SendPasswordResetEmail(user entities.User) error
	SendPasswordResetEmailForUserWithEmail(ctx context.Context, email string) error
}

type emailTemplateDataModel struct {
	Link       string
	SenderName string
}

type emailService struct {
	*sendgrid.Client
	logger *zap.Logger
	cfg    *config.AppConfig
	env    *environment.Env

	paswordResetEmailTemplate *template.Template
	emailVerifyEmailTemplate  *template.Template
}

// NewEmailClient creates a new email client that uses Sendgrid
func NewEmailClient(logger *zap.Logger, cfg *config.AppConfig, env *environment.Env) (EmailService, error) {
	sendgridClient := sendgrid.NewSendClient(env.Get(environment.SendgridAPIKey))

	paswordResetEmailTemplate, err := loadTemplate("password reset", "templates/emails/passwordReset_email.gohtml")
	if err != nil {
		return nil, errors.Wrap(err, "could not load password reset template")
	}

	emailVerifyEmailTemplate, err := loadTemplate("email verify", "templates/emails/emailVerify_email.gohtml")
	if err != nil {
		return nil, errors.Wrap(err, "could not load email verify template")
	}

	return &emailService{
		Client:                    sendgridClient,
		logger:                    logger,
		cfg:                       cfg,
		env:                       env,
		paswordResetEmailTemplate: paswordResetEmailTemplate,
		emailVerifyEmailTemplate:  emailVerifyEmailTemplate,
	}, nil
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
	verificationURL := fmt.Sprintf("http://%s/verifyemail?token=%s", s.cfg.AppURL, emailToken)

	var contentBuff bytes.Buffer
	err := s.paswordResetEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
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

func (s *emailService) SendPasswordResetEmail(user entities.User, emailToken string) error {
	resetURL := fmt.Sprintf("http://%s/resetpwd?email=%s&token=%s", s.cfg.AppURL, user.Email, emailToken)

	var contentBuff bytes.Buffer
	err := s.paswordResetEmailTemplate.Execute(&contentBuff, emailTemplateDataModel{
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

func loadTemplate(templateName string, templatePath string) (*template.Template, error) {
	file, err := os.Open(templatePath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not open template file %s", templatePath)
	}

	templateStr, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read template file %s", templatePath)
	}

	template, err := template.New(templateName).Parse(string(templateStr))
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse template %s", templateName)
	}

	return template, nil
}
