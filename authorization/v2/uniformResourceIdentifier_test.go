package v2

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mock_resources "github.com/unicsmcr/hs_auth/mocks/authorization/v2/resources"
	"github.com/unicsmcr/hs_auth/testutils"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testHandler(*gin.Context) {}

func TestNewUriFromRequest(t *testing.T) {
	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	postFormParams := url.Values{}
	postFormParams.Add("name", "Bob the Tester")
	req := httptest.NewRequest(http.MethodPost, "/test?name=RobTheTester", bytes.NewBufferString(postFormParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.PostForm = postFormParams
	testCtx.Request = req
	testutils.AddUrlParamsToCtx(testCtx, map[string]string{"name": "Bill the Tester"})

	mockRouterResource := mock_resources.NewMockRouterResource(ctrl)
	mockRouterResource.EXPECT().GetResourcePath().Return("test_router").Times(1)

	uri := NewUriFromRequest(mockRouterResource, testHandler, testCtx)

	assert.Equal(t, "test_router:testHandler", uri.path)
	assert.Equal(t, map[string]string{
		"path_name":     "Bill the Tester",
		"query_name":    "RobTheTester",
		"postForm_name": "Bob the Tester",
	}, uri.arguments)
	assert.Nil(t, uri.metadata)
}

func Test_NewURIFromString__should_return_correct_URI(t *testing.T) {
	testURI := "hs:hs_auth:api:v2:provide_access_to_uri"

	expectedURI := UniformResourceIdentifier{
		path:      testURI,
		arguments: nil,
		metadata:  nil,
	}

	actualURI, err := NewURIFromString(testURI)
	assert.NoError(t, err)

	assert.Equal(t, expectedURI, actualURI)
}

func Test_NewURIFromString__should_return_correct_URI_with_arguments(t *testing.T) {
	testURI := "hs:hs_auth:api:v2:provide_access_to_uri?allowed_uri%3Dhs%3Ahs_application%3A%2A"

	expectedURI := UniformResourceIdentifier{
		path:      "hs:hs_auth:api:v2:provide_access_to_uri",
		arguments: map[string]string{"allowed_uri": "hs:hs_application:*"},
		metadata:  nil,
	}

	actualURI, err := NewURIFromString(testURI)
	assert.NoError(t, err)

	assert.Equal(t, expectedURI, actualURI)
}

func Test_NewURIFromString__should_return_correct_URI_with_arguments_and_metadata(t *testing.T) {
	testURI := "hs:hs_auth:api:v2:provide_access_to_uri?allowed_uri%3Dhs%3Ahs_application%3A%2A#until%3D21392103"

	expectedURI := UniformResourceIdentifier{
		path:      "hs:hs_auth:api:v2:provide_access_to_uri",
		arguments: map[string]string{"allowed_uri": "hs:hs_application:*"},
		metadata:  map[string]string{"until": "21392103"},
	}

	actualURI, err := NewURIFromString(testURI)
	assert.NoError(t, err)

	assert.Equal(t, expectedURI, actualURI)
}

func Test_NewURIFromString__should_return_correct_URI_with_metadata(t *testing.T) {
	testURI := "hs:hs_auth:api:v2:provide_access_to_uri#until%3D21392103"

	expectedURI := UniformResourceIdentifier{
		path:      "hs:hs_auth:api:v2:provide_access_to_uri",
		arguments: nil,
		metadata:  map[string]string{"until": "21392103"},
	}

	actualURI, err := NewURIFromString(testURI)
	assert.NoError(t, err)

	assert.Equal(t, expectedURI, actualURI)
}

func Test_NewURIFromString__should_throw_error(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "when malformed arguments provided",
			uri:  "hs:hs_auth:api:v2:provide_access_to_uri?test_arg",
		},
		{
			name: "when malformed metadata provided",
			uri:  "hs:hs_auth:api:v2:provide_access_to_uri#test_arg_metadata",
		},
		{
			name: "when malformed uri provided",
			uri:  "hs:hs_auth:api:v2:provide_access_to_uri#test_arg_metadata%3Dtest1#test_arg2%3Dtest2",
		},
		{
			name: "when malformed url encoded arguments provided",
			uri:  "hs:hs_auth:api:v2:provide_access_to_uri?test_arg%3Dtest1%ZZ",
		},
		{
			name: "when malformed url encoded metadata provided",
			uri:  "hs:hs_auth:api:v2:provide_access_to_uri#test_arg%3Dtest1%NN%UU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testURI := tt.uri
			_, err := NewURIFromString(testURI)
			assert.Error(t, err)
		})
	}
}

func Test_MarshalJSON__should_return_correct_string(t *testing.T) {
	tests := []struct {
		name           string
		uri            UniformResourceIdentifier
		expectedResult string
	}{
		{
			name: "with only path",
			uri: UniformResourceIdentifier{
				path:      "hs:hs_auth:api:v2:provide_access_to_uri",
				arguments: nil,
				metadata:  nil,
			},
			expectedResult: "\"hs:hs_auth:api:v2:provide_access_to_uri\"",
		},
		{
			name: "with path and arguments",
			uri: UniformResourceIdentifier{
				path:      "hs:hs_auth:api:v2:provide_access_to_uri",
				arguments: map[string]string{"allowed_uri": "hs:hs_application:*"},
				metadata:  nil,
			},
			expectedResult: "\"hs:hs_auth:api:v2:provide_access_to_uri?allowed_uri%3Dhs%3Ahs_application%3A%2A\"",
		},
		{
			name: "with path and metadata",
			uri: UniformResourceIdentifier{
				path:      "hs:hs_auth:api:v2:provide_access_to_uri",
				arguments: nil,
				metadata:  map[string]string{"test_arg": "test1"},
			},
			expectedResult: "\"hs:hs_auth:api:v2:provide_access_to_uri#test_arg%3Dtest1\"",
		},
		{
			name: "with path, arguments and metadata",
			uri: UniformResourceIdentifier{
				path:      "hs:hs_auth:api:v2:provide_access_to_uri",
				arguments: map[string]string{"test_arg": "test1"},
				metadata:  map[string]string{"until": "21392103"},
			},
			expectedResult: "\"hs:hs_auth:api:v2:provide_access_to_uri?test_arg%3Dtest1#until%3D21392103\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.uri.MarshalJSON()
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedResult, string(result))
		})
	}
}
