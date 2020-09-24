package v2

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mock_utils "github.com/unicsmcr/hs_auth/mocks/utils"
	"go.uber.org/zap"
	"testing"
	"time"
)

type metadataTestsSetup struct {
	ctrl             *gomock.Controller
	authorizer       *authorizer
	mockTimeProvider *mock_utils.MockTimeProvider
}

func setupMetadataTests(t *testing.T) metadataTestsSetup {
	ctrl := gomock.NewController(t)
	mockTimeProvider := mock_utils.NewMockTimeProvider(ctrl)

	return metadataTestsSetup{
		ctrl: ctrl,
		authorizer: &authorizer{
			timeProvider: mockTimeProvider,
			logger:       zap.NewNop(),
		},
		mockTimeProvider: mockTimeProvider,
	}
}

func TestAuthorizer_validateMetadata__should_return_err_when_identifier_is_unknown(t *testing.T) {
	setup := setupMetadataTests(t)

	_, err := setup.authorizer.validateMetadata("unknown identifier", "")

	assert.Error(t, err)
}

func TestAuthorizer_validateMetadata__should_return_true(t *testing.T) {
	tests := []struct {
		identifier    metadataIdentifier
		prep          func(*metadataTestsSetup)
		givenMetadata string
	}{
		{
			identifier: before,
			prep: func(setup *metadataTestsSetup) {
				setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(1000, 0)).Times(1)
			},
			givenMetadata: "999",
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.identifier), func(t *testing.T) {
			setup := setupMetadataTests(t)
			defer setup.ctrl.Finish()

			tt.prep(&setup)

			result, err := setup.authorizer.validateMetadata(tt.identifier, tt.givenMetadata)

			assert.NoError(t, err)
			assert.True(t, result)
		})
	}
}

func TestAuthorizer_beforeHandler(t *testing.T) {
	const testTime int64 = 1000

	tests := []struct {
		name       string
		timestamp  string
		prep       func(*metadataTestsSetup)
		wantResult bool
		wantErr    bool
	}{
		{
			name:      "should return error when given timestamp is invalid",
			timestamp: "not valid date",
			wantErr:   true,
		},
		{
			name:       "should return true when timestamp is in the past",
			timestamp:  fmt.Sprintf("%d", testTime-1),
			wantResult: true,
		},
		{
			name:       "should return true when timestamp is in the future",
			timestamp:  fmt.Sprintf("%d", testTime+1),
			wantResult: false,
		},
		{
			name:       "should return false when timestamp is the current time",
			timestamp:  fmt.Sprint(testTime),
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupMetadataTests(t)
			setup.mockTimeProvider.EXPECT().Now().Return(time.Unix(testTime, 0))

			result, err := setup.authorizer.beforeHandler(tt.timestamp)

			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}
