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
		Unverified: []common.UniformResourceIdentifier{unverified},
		Applicant:  []common.UniformResourceIdentifier{applicant},
		Attendee:   []common.UniformResourceIdentifier{attendee},
		Volunteer:  []common.UniformResourceIdentifier{volunteer},
		Organiser:  []common.UniformResourceIdentifier{organiser},
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
			expectedResult: roleConfig[Unverified],
		},
		{
			name:           "applicant",
			expectedResult: roleConfig[Applicant],
		},
		{
			name:           "attendee",
			expectedResult: roleConfig[Attendee],
		},
		{
			name:           "volunteer",
			expectedResult: roleConfig[Volunteer],
		},
		{
			name:           "organiser",
			expectedResult: roleConfig[Organiser],
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

func Test_ValidateRole__should_return_nil_for_existing_roles(t *testing.T) {
	roleConfig := testSetupRoleConfig()

	tests := []struct {
		role string
	}{
		{"unverified"},
		{"applicant"},
		{"attendee"},
		{"volunteer"},
		{role: "organiser"},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			err := roleConfig.ValidateRole(UserRole(tt.role))
			assert.NoError(t, err)
		})
	}
}

func Test_ValidateRole__should_return_error_for_non_existant_role(t *testing.T) {
	roleConfig := testSetupRoleConfig()

	assert.Error(t, roleConfig.ValidateRole(UserRole("non-existant role")))
}

func TestUserRole_UnmarshalJSON__should_return_correct_role_for_registered_role_strings(t *testing.T) {
	tests := []struct {
		name         string
		stringRole   string
		expectedRole UserRole
	}{
		{
			name:         "unverified",
			stringRole:   "\"unverified\"",
			expectedRole: Unverified,
		},
		{
			name:         "applicant",
			stringRole:   "\"applicant\"",
			expectedRole: Applicant,
		},
		{
			name:         "attendee",
			stringRole:   "\"attendee\"",
			expectedRole: Attendee,
		},
		{
			name:         "volunteer",
			stringRole:   "\"volunteer\"",
			expectedRole: Volunteer,
		},
		{
			name:         "organiser",
			stringRole:   "\"organiser\"",
			expectedRole: Organiser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testRole UserRole
			err := testRole.UnmarshalJSON([]byte(tt.stringRole))
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedRole, testRole)
		})
	}
}

func TestUserRole_UnmarshalJSON__should_return_ErrUnknownRole_for_unknown_roles(t *testing.T) {
	stringRole := "test"

	var testRole UserRole
	err := testRole.UnmarshalJSON([]byte(stringRole))
	assert.Error(t, err)
}

func TestUserRole_UnmarshalJSON__should_return_ErrUnknownRole_for_no_role(t *testing.T) {
	stringRole := ""

	var testRole UserRole
	err := testRole.UnmarshalJSON([]byte(stringRole))
	assert.Error(t, err)
}
