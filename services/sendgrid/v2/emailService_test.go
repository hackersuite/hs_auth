package v2

import (
	"github.com/sendgrid/sendgrid-go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	_sendgridAPIKey    = "testkey"
	_testEmailTemplate = "../testEmailTemplate.txt"
)

type response struct {
	message string
	status  int
}

func getTestClient(t *testing.T, expectedRequestBody string, wantResponse response) (*sendgrid.Client, *httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(expectedRequestBody) != 0 {
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.Equal(t, expectedRequestBody, string(body))
		}
		w.WriteHeader(wantResponse.status)
		w.Write([]byte(wantResponse.message))
	}))

	req := sendgrid.GetRequest(_sendgridAPIKey, "/", server.URL)
	req.Method = http.MethodPost
	client := sendgrid.Client{
		Request: req,
	}

	return &client, server
}

func Test_NewSendgridEmailService__should_return_error_when_template_path_is_incorrect(t *testing.T) {
	// password reset
	passwordResetEmailTemplatePath = "invalid path"
	emailVerifyEmailTemplatePath = _testEmailTemplate

	service, err := NewSendgridEmailServiceV2(nil, nil, nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)

	// email verify
	emailVerifyEmailTemplatePath = "invalid path"
	passwordResetEmailTemplatePath = _testEmailTemplate

	service, err = NewSendgridEmailServiceV2(nil, nil, nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)
}

func Test_SendEmail__should_send_correct_message_to_sendgrid(t *testing.T) {
	passwordResetEmailTemplatePath = "../testEmailTemplate.txt"
	emailVerifyEmailTemplatePath = "../testEmailTemplate.txt"

	client, server := getTestClient(t, `{"from":{"name":"Bob the Tester","email":"bob@test.com"},"subject":"test email","personalizations":[{"to":[{"name":"Rob the Tester","email":"rob@test.com"}]}],"content":[{"type":"text/plain","value":"test email body"},{"type":"text/html","value":"test email body"}]}`,
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	service, err := NewSendgridEmailServiceV2(zap.NewNop(), nil, nil, client, nil, nil)
	assert.NoError(t, err)

	err = service.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.NoError(t, err)
}

func Test_SendEmail__should_return_error_when_sendgrid_rejects_request(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	client, server := getTestClient(t, "",
		response{
			status: http.StatusUnauthorized,
		})
	defer server.Close()

	service, err := NewSendgridEmailServiceV2(zap.NewNop(), nil, nil, client, nil, nil)
	assert.NoError(t, err)

	err = service.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.Error(t, err)
}
