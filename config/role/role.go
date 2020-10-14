package role

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"strconv"
)

type UserRole string

const Unverified UserRole = "unverified"
const Applicant UserRole = "applicant"
const Attendee UserRole = "attendee"
const Volunteer UserRole = "volunteer"
const Organiser UserRole = "organiser"

// RoleConfig stores the configuration to be used by the v2 authorizer
type UserRoleConfig map[UserRole]common.UniformResourceIdentifiers

func (r UserRoleConfig) GetRolePermissions(role UserRole) (common.UniformResourceIdentifiers, error) {
	uris, ok := r[role]
	if !ok {
		return nil, errors.Wrap(common.ErrUnknownRole, fmt.Sprintf("role %s does not exist", role))
	}
	return uris, nil
}

func (r *UserRole) UnmarshalJSON(data []byte) error {
	// Ignore the error from Unquote as invalid roles will be caught below
	role, _ := strconv.Unquote(string(data))

	switch UserRole(role) {
	case Unverified, Applicant, Attendee, Volunteer, Organiser:
		*r = UserRole(role)
		return nil
	}

	return common.ErrUnknownRole
}
