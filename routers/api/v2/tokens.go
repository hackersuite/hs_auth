package v2

import (
	"github.com/gin-gonic/gin"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// POST: /api/v2/tokens/service
// x-www-form-urlencoded
// Request:	 owner string
//			 allowedURIs string
//			 expiresAt int64
// Response: token string
// Headers:  Authorization <- token
func (r *apiV2Router) CreateServiceToken(ctx *gin.Context) {
	var req struct {
		Owner       string `form:"owner"`
		AllowedURIs string `form:"allowedURIs"`
		ExpiresAt   int64  `form:"expiresAt"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		r.logger.Debug(err.Error())
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse request")
		return
	}

	if len(req.Owner) == 0 {
		r.logger.Debug("token owner was not provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "token owner must be provided")
		return
	}

	if len(req.AllowedURIs) == 0 {
		r.logger.Debug("no allowedURIs were provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "at least one allowedURI must be provided")
		return
	}

	uriList := strings.Split(req.AllowedURIs, ",")
	parsedURIs := make([]v2.UniformResourceIdentifier, len(uriList))
	for i, uriString := range uriList {
		err = parsedURIs[i].UnmarshalJSON([]byte(uriString))
		if err != nil {
			r.logger.Error("provided URI could not be parsed", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid URI string in allowedURIs")
			return
		}
	}

	token, err := r.authorizer.CreateServiceToken(req.Owner, parsedURIs, req.ExpiresAt)
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.JSON(http.StatusOK, serviceTokenRes{
		Token: token,
	})
}
