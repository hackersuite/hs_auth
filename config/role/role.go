package role

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
)

type UserRole string

const Unverified UserRole = "unverified"
const Applicant UserRole = "applicant"
const Attendee UserRole = "attendee"
const Volunteer UserRole = "volunteer"
const Organiser UserRole = "organiser"

// RoleConfig stores the configuration to be used by the v2 authorizer
type UserRoleConfig map[string]common.UniformResourceIdentifiers

func (r UserRoleConfig) GetRolePermissions(role UserRole) (common.UniformResourceIdentifiers, error) {
	uris, ok := r[string(role)]
	if !ok {
		return nil, errors.Wrap(common.ErrUnknownRole, fmt.Sprintf("role %s does not exist", role))
	}
	return uris, nil
}
