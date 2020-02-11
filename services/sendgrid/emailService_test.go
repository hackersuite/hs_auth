package sendgrid

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sendgrid/sendgrid-go"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

const (
	_sendgridAPIKey    = "testkey"
	_testEmailTemplate = "testEmailTemplate.txt"
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

	service, err := NewSendgridEmailService(nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)

	// email verify
	emailVerifyEmailTemplatePath = "invalid path"
	passwordResetEmailTemplatePath = _testEmailTemplate

	service, err = NewSendgridEmailService(nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)
}

func Test_SendEmail__should_send_correct_message_to_sendgrid(t *testing.T) {
	passwordResetEmailTemplatePath = "testEmailTemplate.txt"
	emailVerifyEmailTemplatePath = "testEmailTemplate.txt"

	client, server := getTestClient(t, `{"from":{"name":"Bob the Tester","email":"bob@test.com"},"subject":"test email","personalizations":[{"to":[{"name":"Rob the Tester","email":"rob@test.com"}]}],"content":[{"type":"text/plain","value":"test email body"},{"type":"text/html","value":"test email body"}]}`,
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	service, err := NewSendgridEmailService(zap.NewNop(), nil, client, nil)
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

	service, err := NewSendgridEmailService(zap.NewNop(), nil, client, nil)
	assert.NoError(t, err)

	err = service.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.Error(t, err)
}

func Test_SendEmailVerificationEmail__should_not_return_error_when_sending_email_is_successful(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	client, server := getTestClient(t, "",
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	service, err := NewSendgridEmailService(zap.NewNop(), &config.AppConfig{
		Email: config.EmailConfig{
			NoreplyEmailAddr:          "bob@test.com",
			NoreplyEmailName:          "Bob the Tester",
			EmailVerficationEmailSubj: "test subject",
		},
	}, client, nil)
	assert.NoError(t, err)

	err = service.SendEmailVerificationEmail(entities.User{
		Name:  "Rob the Tester",
		Email: "rob@test.com",
	})
	assert.NoError(t, err)
}

func Test_SendEmailVerificationEmailForUserWithEmail__should_make_correct_call_to_user_service(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	client, server := getTestClient(t, "",
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "bob@test.com").
		Return(&entities.User{
			Name:  "Bob the Tester",
			Email: "bob@test.com",
		}, nil).Times(1)

	service, err := NewSendgridEmailService(zap.NewNop(), &config.AppConfig{
		Email: config.EmailConfig{},
	}, client, mockUService)
	assert.NoError(t, err)

	err = service.SendEmailVerificationEmailForUserWithEmail(context.Background(), "bob@test.com")
	assert.NoError(t, err)
}

func Test_SendPasswordResetEmail__should_not_return_error_when_sending_email_is_successful(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	client, server := getTestClient(t, "",
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	service, err := NewSendgridEmailService(zap.NewNop(), &config.AppConfig{
		Email: config.EmailConfig{
			NoreplyEmailAddr:          "bob@test.com",
			NoreplyEmailName:          "Bob the Tester",
			EmailVerficationEmailSubj: "test subject",
		},
	}, client, nil)
	assert.NoError(t, err)

	err = service.SendPasswordResetEmail(entities.User{
		Name:  "Rob the Tester",
		Email: "rob@test.com",
	})
	assert.NoError(t, err)
}

func Test_SendPasswordResetEmailForUserWithEmail__should_make_correct_call_to_user_service(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	client, server := getTestClient(t, "",
		response{
			status: http.StatusAccepted,
		})
	defer server.Close()

	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "bob@test.com").
		Return(&entities.User{
			Name:  "Bob the Tester",
			Email: "bob@test.com",
		}, nil).Times(1)

	service, err := NewSendgridEmailService(zap.NewNop(), &config.AppConfig{
		Email: config.EmailConfig{},
	}, client, mockUService)
	assert.NoError(t, err)

	err = service.SendPasswordResetEmailForUserWithEmail(context.Background(), "bob@test.com")
	assert.NoError(t, err)
}

func Test_SendEmailVerificationEmailForUserWithEmail__should_return_error_when_user_service_returns_error(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "bob@test.com").
		Return(nil, services.ErrNotFound).Times(1)

	service := &sendgridEmailService{
		userService: mockUService,
	}

	err := service.SendEmailVerificationEmailForUserWithEmail(context.Background(), "bob@test.com")
	assert.Equal(t, services.ErrNotFound, err)
}

func Test_SendPasswordResetEmailForUserWithEmail__should_return_error_when_user_service_returns_error(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockUService.EXPECT().GetUserWithEmail(gomock.Any(), "bob@test.com").
		Return(nil, services.ErrNotFound).Times(1)

	service := &sendgridEmailService{
		userService: mockUService,
	}

	err := service.SendPasswordResetEmailForUserWithEmail(context.Background(), "bob@test.com")
	assert.Equal(t, services.ErrNotFound, err)
}
