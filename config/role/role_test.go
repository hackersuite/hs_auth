package role

import (
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"testing"
)

func testSetupRoleConfig() UserRoleConfig {
	unverified, _ := common.NewURIFromString("hs:unverified")
	applicant, _ := common.NewURIFromString("hs:applicant")
	attendee, _ := common.NewURIFromString("hs:attendee")
	volunteer, _ := common.NewURIFromString("hs:volunteer")
	organiser, _ := common.NewURIFromString("hs:organiser")

	return UserRoleConfig{
		"unverified": []common.UniformResourceIdentifier{unverified},
		"applicant":  []common.UniformResourceIdentifier{applicant},
		"attendee":   []common.UniformResourceIdentifier{attendee},
		"volunteer":  []common.UniformResourceIdentifier{volunteer},
		"organiser":  []common.UniformResourceIdentifier{organiser},
	}
}

func Test_GetRolePermissions__should_return_correct_uri_set_for_each_role(t *testing.T) {
	roleConfig := testSetupRoleConfig()

	tests := []struct {
		name           string
		expectedResult common.UniformResourceIdentifiers
	}{
		{
			name:           "unverified",
			expectedResult: roleConfig["unverified"],
		},
		{
			name:           "applicant",
			expectedResult: roleConfig["applicant"],
		},
		{
			name:           "attendee",
			expectedResult: roleConfig["attendee"],
		},
		{
			name:           "volunteer",
			expectedResult: roleConfig["volunteer"],
		},
		{
			name:           "organiser",
			expectedResult: roleConfig["organiser"],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := roleConfig.GetRolePermissions(UserRole(tt.name))
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func Test_GetRolePermissions__should_return_error_with_invalid_role(t *testing.T) {
	roleConfig := testSetupRoleConfig()

	_, err := roleConfig.GetRolePermissions("test")
	assert.Error(t, err)
}
