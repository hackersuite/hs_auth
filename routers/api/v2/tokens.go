package v2

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
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
	parsedURIs := make([]common.UniformResourceIdentifier, len(uriList))
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
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		default:
			r.logger.Error("could not extract token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	token, err := r.authorizer.CreateServiceToken(ctx, userID, parsedURIs, req.ExpiresAt)
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
// Headers:  Authorization -> token
func (r *apiV2Router) InvalidateServiceToken(ctx *gin.Context) {
	tokenID := ctx.Param("id")
	if len(tokenID) == 0 {
		r.logger.Debug("token id must be provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "token id must be provided")
		return
	}

	err := r.authorizer.InvalidateServiceToken(ctx, tokenID)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("service token id is not valid", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid id")
		case services.ErrNotFound:
			r.logger.Debug("service token not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "service token not found")
		default:
			r.logger.Error("could not invalidate token", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// GET: /api/v2/tokens/resources/authorized?from={authorisedUris}&user={userId}
// Request:	 authorisedUris string
//           (Optional) userId primitive.ObjectID
// Response: authorisedUris []common.UniformResourceIdentifier
// Headers:  Authorization -> token
func (r *apiV2Router) GetAuthorizedResources(ctx *gin.Context) {
	fromUris := ctx.Query("from")

	fromUris, err := url.QueryUnescape(fromUris)
	if err != nil {
		r.logger.Debug("could not unescape query parameters in request", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse set of requested resources")
		return
	}

	var requestedUris common.UniformResourceIdentifiers
	err = json.Unmarshal([]byte(fromUris), &requestedUris)
	if err != nil {
		r.logger.Debug("could not parse uri array")
		models.SendAPIError(ctx, http.StatusBadRequest, "provided uri could not be parsed")
		return
	}

	var authorizedUris []common.UniformResourceIdentifier
	if len(ctx.Query("user")) > 0 {
		var userId primitive.ObjectID
		userId, err = primitive.ObjectIDFromHex(ctx.Query("user"))
		if err != nil {
			r.logger.Debug("invalid user id", zap.String("userId", ctx.Query("user")))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided user id is invalid")
			return
		}
		authorizedUris, err = r.authorizer.GetAuthorizedResourcesForUser(ctx, userId, requestedUris)
	} else {
		token := r.GetAuthToken(ctx)
		authorizedUris, err = r.authorizer.GetAuthorizedResources(ctx, token, requestedUris)
	}
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("userId", ctx.Query("user")), zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user with given does not exist")
		default:
			r.logger.Error("could not get authorized URIs", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}
	if authorizedUris == nil {
		authorizedUris = common.UniformResourceIdentifiers{}
	}

	ctx.JSON(http.StatusOK, getAuthorizedResourcesRes{
		AuthorizedUris: authorizedUris,
	})
}
