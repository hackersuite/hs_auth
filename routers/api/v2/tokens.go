package v2

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

// POST: /api/v2/tokens/service
// x-www-form-urlencoded
// Request:  allowedURIs string
//			 expiresAt int64
// Response: token string
// Headers:  Authorization <- token
func (r *apiV2Router) CreateServiceToken(ctx *gin.Context) {
	var req struct {
		AllowedURIs string `form:"allowedURIs"`
		ExpiresAt   int64  `form:"expiresAt"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		r.logger.Debug("could not parse service token request", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse request")
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
		err := json.Unmarshal([]byte(uriString), &parsedURIs[i])
		if err != nil {
			r.logger.Debug("provided URI could not be parsed", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid URI string in allowedURIs")
			return
		}
	}

	userToken := r.GetAuthToken(ctx)
	userID, err := r.authorizer.GetUserIdFromToken(userToken)
	if err != nil {
		r.logger.Debug("could not extract id from auth token", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "could not extract user id from auth token")
		return
	}

	tokenID := primitive.NewObjectID()
	token, err := r.authorizer.CreateServiceToken(tokenID, parsedURIs, req.ExpiresAt)
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	_, err = r.tokenService.AddServiceToken(ctx, tokenID, userID.Hex(), token)
	if err != nil {
		r.logger.Error("could not create service token", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.JSON(http.StatusOK, serviceTokenRes{
		Token: token,
	})
}

// DELETE: /api/v2/tokens/service/:id
// Response:
// Headers:  Authorization <- token
func (r *apiV2Router) DeleteServiceToken(ctx *gin.Context) {
	tokenID := ctx.Param("id")
	if len(tokenID) == 0 {
		r.logger.Debug("token id must be provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "token id must be provided")
		return
	}

	err := r.tokenService.DeleteServiceToken(ctx, tokenID)
	if err != nil {
		r.logger.Error("could not delete service token", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.Status(http.StatusNoContent)
}