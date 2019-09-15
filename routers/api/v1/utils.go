package v1

import (
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/utils/auth"
)

func extractClaimsFromCtx(ctx *gin.Context) *auth.Claims {
	claimsEncoded, exists := ctx.Get(authClaimsKeyInCtx)
	if !exists {
		return nil
	}
	claims, ok := claimsEncoded.(*auth.Claims)
	if !ok {
		return nil
	}
	return claims
}
