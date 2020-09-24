package services

import (
	"context"
	"github.com/unicsmcr/hs_auth/entities"
)

// EmailServiceV2 is used to send out emails
type EmailServiceV2 interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error

	SendEmailVerificationEmail(user entities.User, emailVerificationResourcePath string) error
	SendEmailVerificationEmailForUserWithEmail(ctx context.Context, email string, emailVerificationResourcePath string) error

	SendPasswordResetEmail(user entities.User, passwordResetResourcePath string) error
	SendPasswordResetEmailForUserWithEmail(ctx context.Context, email string, passwordResetResourcePath string) error
}
