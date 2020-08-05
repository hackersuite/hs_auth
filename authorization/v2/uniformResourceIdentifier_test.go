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
