package v1

import (
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/unicsmcr/hs_auth/utils/auth"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

func Test_extractClaimsFromCtx__should_return_nil_when_ctx_doesnt_have_auth_claims(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())

	claims := extractClaimsFromCtx(testCtx)
	assert.Nil(t, claims)
}

func Test_extractClaimsFromCtx__should_return_nil_when_claims_in_ctx_are_of_different_type(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())

	testCtx.Set(authClaimsKeyInCtx, true)

	claims := extractClaimsFromCtx(testCtx)
	assert.Nil(t, claims)
}

func Test_extractClaimsFromCtx__should_return_correct_claims(t *testing.T) {
	testCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	expectedClaims := &auth.Claims{
		StandardClaims: jwt.StandardClaims{
			Id: "test id",
		},
	}

	testCtx.Set(authClaimsKeyInCtx, expectedClaims)

	claims := extractClaimsFromCtx(testCtx)
	assert.Equal(t, expectedClaims, claims)
}
