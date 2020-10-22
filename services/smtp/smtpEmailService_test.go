package smtp

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
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
	"net/http/httptest"
	"net/smtp"
	"testing"
	"time"
)

const (
	_testEmailTemplate = "./testEmailTemplate.txt"
	testServer         = "localhost"
	testPort           = "1234"
	testUsername       = "username"
	testPassword       = "password"
)

var (
	testUserId = primitive.NewObjectID()
	testAuth   = smtp.PlainAuth("", testUsername, testPassword, testServer)
)

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
	mockSMTPClient   *mock_utils.MockSMTPClient
	testCtx          *gin.Context
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
	emailVerifyEmailTemplatePath = _testEmailTemplate
	passwordResetEmailTemplatePath = _testEmailTemplate

	ctrl := gomock.NewController(t)
	mockAuthorizer := mock_v2.NewMockAuthorizer(ctrl)
	mockUService := mock_services.NewMockUserService(ctrl)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)
	mockSMTPClient := mock_utils.NewMockSMTPClient(ctrl)
	testCfgCopy := testCfg

	restore := testutils.SetEnvVars(map[string]string{
		environment.SMTPHost:     testServer,
		environment.SMTPPort:     testPort,
		environment.SMTPUsername: testUsername,
		environment.SMTPPassword: testPassword,
	})
	env := environment.NewEnv(zap.NewNop())
	defer restore()

	emailService, err := NewSMPTEmailService(&testCfgCopy, env, mockSMTPClient, mockUService, mockAuthorizer, mockTimeProvider)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	return &emailTestSetup{
		ctrl:             ctrl,
		emailService:     emailService,
		mockUService:     mockUService,
		mockAuthorizer:   mockAuthorizer,
		mockTimeProvider: mockTimeProvider,
		mockSMTPClient:   mockSMTPClient,
		testCtx:          testCtx,
	}
}

func Test_NewSMTPEmailService__should_return_error_when_template_path_is_incorrect(t *testing.T) {
	// password reset
	passwordResetEmailTemplatePath = "invalid path"
	emailVerifyEmailTemplatePath = _testEmailTemplate

	service, err := NewSMPTEmailService(nil, nil, nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)

	// email verify
	emailVerifyEmailTemplatePath = "invalid path"
	passwordResetEmailTemplatePath = _testEmailTemplate

	service, err = NewSMPTEmailService(nil, nil, nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, service)
}

func Test_SendEmail__should_send_correct_message_to_smtp(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()

	setup.mockSMTPClient.EXPECT().SendEmail(fmt.Sprintf("%s:%s", testServer, testPort), testAuth,
		"bob@test.com", []string{"rob@test.com"}, gomock.Any()).Return(nil).Times(1)

	err := setup.emailService.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.NoError(t, err)
}

func Test_SendEmail__should_return_error_when_sending_email_fails(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()

	setup.mockSMTPClient.EXPECT().SendEmail(fmt.Sprintf("%s:%s", testServer, testPort), testAuth,
		"bob@test.com", []string{"rob@test.com"}, gomock.Any()).Return(errors.New("smtp err")).Times(1)

	err := setup.emailService.SendEmail("test email", "test email body", "test email body",
		"Bob the Tester", "bob@test.com", "Rob the Tester", "rob@test.com")

	assert.Error(t, err)
}

func Test_SendEmailVerificationEmail__should_not_return_error_when_sending_email_is_successful(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	testURI, _ := common.NewURIFromString("test")

	setup.mockSMTPClient.EXPECT().SendEmail(fmt.Sprintf("%s:%s", testServer, testPort), testAuth,
		testCfg.Email.NoreplyEmailAddr, []string{"rob@test.com"}, gomock.Any()).Return(nil).Times(1)
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", nil).Times(1)

	err := setup.emailService.SendEmailVerificationEmail(setup.testCtx, entities.User{
		ID:    testUserId,
		Email: "rob@test.com",
	}, []common.UniformResourceIdentifier{testURI})
	assert.NoError(t, err)
}

func Test_SendEmailVerificationEmail__should_return_error_when_authorizer_returns_error(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	testURI, _ := common.NewURIFromString("test")

	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", errors.New("authorizer err")).Times(1)

	err := setup.emailService.SendPasswordResetEmail(setup.testCtx, entities.User{
		ID: testUserId,
	}, []common.UniformResourceIdentifier{testURI})

	assert.Error(t, err)
}

func Test_SendPasswordResetEmail__should_not_return_error_when_sending_email_is_successful(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	testURI, _ := common.NewURIFromString("test")

	setup.mockSMTPClient.EXPECT().SendEmail(fmt.Sprintf("%s:%s", testServer, testPort), testAuth,
		testCfg.Email.NoreplyEmailAddr, []string{"rob@test.com"}, gomock.Any()).Return(nil).Times(1)
	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", nil).Times(1)

	err := setup.emailService.SendPasswordResetEmail(setup.testCtx, entities.User{
		ID:    testUserId,
		Email: "rob@test.com",
	}, []common.UniformResourceIdentifier{testURI})
	assert.NoError(t, err)
}

func Test_SendPasswordResetEmail__should_return_error_when_authorizer_returns_error(t *testing.T) {
	setup := setupEmailTest(t)
	defer setup.ctrl.Finish()
	testURI, _ := common.NewURIFromString("test")

	setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1, 0)).Times(1)
	setup.mockAuthorizer.EXPECT().CreateServiceToken(setup.testCtx, testUserId, []common.UniformResourceIdentifier{testURI}, int64(1001)).
		Return("", errors.New("authorizer err")).Times(1)

	err := setup.emailService.SendEmailVerificationEmail(setup.testCtx, entities.User{
		ID: testUserId,
	}, []common.UniformResourceIdentifier{testURI})

	assert.Error(t, err)
}
