package multiplexers

import (
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"testing"
)

func Test_NewEmailServiceV2__returns_err_when_email_delivery_provider_not_valid(t *testing.T) {
	_, err := NewEmailServiceV2(&config.AppConfig{
		Email: config.EmailConfig{
			EmailDeliveryProvider: "invalid provider",
		},
	}, nil, nil, nil, nil, nil, nil)

	assert.Error(t, err)
}
