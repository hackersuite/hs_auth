package common

import (
	"fmt"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/entities"
)

const ApiV2ResourcePath = "hs:hs_auth:api:v2"
const FrontendResourcePath = "hs:hs_auth:frontend"

func MakeEmailVerificationURIs(user entities.User) common.UniformResourceIdentifiers {
	apiV2Uri, _ := common.NewURIFromString(fmt.Sprintf("%s:VerifyEmail?path_id=%s", ApiV2ResourcePath, user.ID.Hex()))
	frontendUri, _ := common.NewURIFromString(fmt.Sprintf("%s:VerifyEmail?query_userId=%s", FrontendResourcePath, user.ID.Hex()))

	return []common.UniformResourceIdentifier{apiV2Uri, frontendUri}
}

func MakePasswordResetURIs(user entities.User) common.UniformResourceIdentifiers {
	apiV2Uri, _ := common.NewURIFromString(fmt.Sprintf("%s:SetPassword?path_id=%s", ApiV2ResourcePath, user.ID.Hex()))
	frontendUri, _ := common.NewURIFromString(fmt.Sprintf("%s:ResetPassword?query_userId=%s", FrontendResourcePath, user.ID.Hex()))

	return []common.UniformResourceIdentifier{apiV2Uri, frontendUri}
}
