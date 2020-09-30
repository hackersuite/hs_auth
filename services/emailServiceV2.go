package services

import (
	"context"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/entities"
)

// EmailServiceV2 is used to send out emails
type EmailServiceV2 interface {
	SendEmail(subject, htmlBody, plainTextBody, senderName, senderEmail, recipientName, recipientEmail string) error

	SendEmailVerificationEmail(ctx context.Context, user entities.User, emailVerificationResources []common.UniformResourceIdentifier) error

	SendPasswordResetEmail(ctx context.Context, user entities.User, passwordResetResources []common.UniformResourceIdentifier) error
}
