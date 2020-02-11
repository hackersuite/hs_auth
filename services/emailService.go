package services

import (
	"context"

	"github.com/unicsmcr/hs_auth/entities"
)

// EmailService is used to send out emails
type EmailService interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error

	SendEmailVerificationEmail(user entities.User) error
	SendEmailVerificationEmailForUserWithEmail(ctx context.Context, email string) error

	SendPasswordResetEmail(user entities.User) error
	SendPasswordResetEmailForUserWithEmail(ctx context.Context, email string) error
}
