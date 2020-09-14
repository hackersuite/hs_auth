package v2

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
	"net/http"
	"net/url"
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
		r.logger.Debug("could not parse service token request", zap.Error(err))
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
		err := json.Unmarshal([]byte(uriString), &parsedURIs[i])
		if err != nil {
			r.logger.Debug("provided URI could not be parsed", zap.Error(err))
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

// GET: /api/v2/tokens/resources/authorized?from={authorisedUris}
// Request:	 authorisedUris string
// Response: authorisedUris []v2.UniformResourceIdentifier
// Headers:  Authorization <- token
func (r *apiV2Router) GetAuthorizedResources(ctx *gin.Context) {
	fromUris := ctx.Query("from")
	if len(fromUris) == 0 {
		r.logger.Debug("could not parse get authorized resources request")
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse request")
		return
	}

	fromUris, err := url.QueryUnescape(fromUris)
	if err != nil {
		r.logger.Debug("could not parse get authorized resources request", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse request")
		return
	}

	// Remove the leading '[' and trailing ']' from the uri parameter
	fromUris = fromUris[1 : len(fromUris)-1]
	rawUriList := strings.Split(fromUris, ",")

	var requestedUris = make([]v2.UniformResourceIdentifier, len(rawUriList))
	for i, rawUri := range rawUriList {
		err := requestedUris[i].UnmarshalJSON([]byte(rawUri))
		if err != nil {
			r.logger.Debug(fmt.Sprintf("uri could not be parsed at index %d", i))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided uri could not be parsed")
			return
		}
	}

	token := r.GetAuthToken(ctx)
	authorizedUris, err := r.authorizer.GetAuthorizedResources(token, requestedUris)
	if err != nil {
		switch errors.Cause(err) {
		case v2.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not get authorized URIs", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, getAuthorizedResourcesRes{
		AuthorizedUris: authorizedUris,
	})
}
