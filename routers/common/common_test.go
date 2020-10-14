package common

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/url"
	"testing"
)

var testUserId = primitive.NewObjectID()

func TestMakeEmailVerificationURIs(t *testing.T) {
	uris := MakeEmailVerificationURIs(entities.User{ID: testUserId})

	assert.Len(t, uris, 2)

	apiV2Uri, err := uris[0].MarshalJSON()
	assert.NoError(t, err)
	unescapedApiV2Uri, err := url.QueryUnescape(string(apiV2Uri))
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("\"hs:hs_auth:api:v2:VerifyEmail?path_id=%s\"", testUserId.Hex()), unescapedApiV2Uri)
	frontendUri, err := uris[1].MarshalJSON()
	assert.NoError(t, err)
	unescapedFrontendUri, err := url.QueryUnescape(string(frontendUri))
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("\"hs:hs_auth:frontend:VerifyEmail?query_userId=%s\"", testUserId.Hex()), unescapedFrontendUri)
}

func TestMakePasswordResetURIs(t *testing.T) {
	uris := MakePasswordResetURIs(entities.User{ID: testUserId})

	assert.Len(t, uris, 2)

	apiV2Uri, err := uris[0].MarshalJSON()
	assert.NoError(t, err)
	unescapedApiV2Uri, err := url.QueryUnescape(string(apiV2Uri))
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("\"hs:hs_auth:api:v2:SetPassword?path_id=%s\"", testUserId.Hex()), unescapedApiV2Uri)
	frontendUri, err := uris[1].MarshalJSON()
	assert.NoError(t, err)
	unescapedFrontendUri, err := url.QueryUnescape(string(frontendUri))
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("\"hs:hs_auth:frontend:ResetPassword?query_userId=%s\"", testUserId.Hex()), unescapedFrontendUri)
}
