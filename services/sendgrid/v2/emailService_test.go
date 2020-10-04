package v2

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/sendgrid/sendgrid-go"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	mock_v2 "github.com/unicsmcr/hs_auth/mocks/authorization/v2"
	mock_services "github.com/unicsmcr/hs_auth/mocks/services"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	_sendgridAPIKey    = "testkey"
	_testEmailTemplate = "../testEmailTemplate.txt"
)

var testUserId = primitive.NewObjectID()

type response struct {
	message string
	status  int
}

type emailTestSetup struct {
	ctrl             *gomock.Controller
	emailService     services.EmailServiceV2
	mockUService     *mock_services.MockUserService
	mockAuthorizer   *mock_v2.MockAuthorizer
	mockTimeProvider *mock_utils.MockTimeProvider
	testCtx          *gin.Context
	emailServer      *httptest.Server
}

var testCfg = config.AppConfig{
	Email: config.EmailConfig{
		NoreplyEmailAddr:           "bob@test.com",
		NoreplyEmailName:           "Bob the Tester",
		EmailVerificationEmailSubj: "test subject",
		TokenLifetime:              1000,
	},
}

func setupEmailTest(t *testing.T) *emailTestSetup {
	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)
	testCfgCopy := testCfg
	restore := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: "test",
	})
	defer restore()
	env := environment.NewEnv(zap.NewNop())
	client, server := getTestClient(t, "",
		response{
			status: http.StatusAccepted,
		})

	emailService, _ := NewSendgridEmailServiceV2(&testCfgCopy, env, client, mockUService, mockAuthorizer, mockTimeProvider)
	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	return &emailTestSetup{
		ctrl:             ctrl,
		emailService:     emailService,
		mockUService:     mockUService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		testCtx:          testCtx,
		emailServer:      server,
	}
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

	service, err := NewSendgridEmailServiceV2(nil, nil, client, nil, nil, nil)
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

	service, err := NewSendgridEmailServiceV2(nil, nil, client, nil, nil, nil)
	assert.NoError(t, err)

	err = service.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.Error(t, err)
}

func Test_SendEmailVerificationEmail__should_not_return_error_when_sending_email_is_successful(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	defer setup.emailServer.Close()
	testURI, _ := common.NewURIFromString("test")
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", nil).Times(1)

	err := setup.emailService.SendEmailVerificationEmail(setup.testCtx, entities.User{
		ID: testUserId,
	}, []common.UniformResourceIdentifier{testURI})
	assert.NoError(t, err)
}

func Test_SendEmailVerificationEmail__should_return_error_when_authorizer_returns_error(t *testing.T) {
	passwordResetEmailTemplatePath = _testEmailTemplate
	emailVerifyEmailTemplatePath = _testEmailTemplate

	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	defer setup.emailServer.Close()
	testURI, _ := common.NewURIFromString("test")
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", errors.New("authorizer err")).Times(1)

	err := setup.emailService.SendEmailVerificationEmail(setup.testCtx, entities.User{
		ID: testUserId,
	}, []common.UniformResourceIdentifier{testURI})
	assert.Error(t, err)
}
