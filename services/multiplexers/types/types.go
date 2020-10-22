package types

type EmailDeliveryProvider string

const (
	SMTP     EmailDeliveryProvider = "smtp"
	SendGrid EmailDeliveryProvider = "sendgrid"
)
