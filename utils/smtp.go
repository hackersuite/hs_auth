package utils

import "net/smtp"

// SMTPClient provides access to the smtp.SendEmail function through an interface
// in order to make mocking of sending an email possible
type SMTPClient interface {
	SendEmail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

func NewSMTPClient() SMTPClient {
	return &smtpClient{}
}

type smtpClient struct{}

func (*smtpClient) SendEmail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}
