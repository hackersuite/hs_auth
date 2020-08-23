package v2

import (
	"github.com/gin-gonic/gin"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"strings"
)

func (r *apiV2Router) ServiceToken(ctx *gin.Context) {
	owner := ctx.PostForm("owner")
	allowedURIs := ctx.PostForm("allowedURIs")
	expiresAt := ctx.PostForm("expiresAt")

	if len(owner) == 0 {
		r.logger.Debug("service name was not provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "service name for the token must be provided")
		return
	}

	if len(allowedURIs) == 0 {
		r.logger.Debug("no allowedURIs were provided in request")
		models.SendAPIError(ctx, http.StatusBadRequest, "at least one allowedURI must be provided")
		return
	}

	// expiresAt is optional in the form, the default value is -1, i.e. never expires
	if len(expiresAt) == 0 {
		expiresAt = "-1"
	}

	uriList := strings.Split(allowedURIs, ",")
	var parsedURIs []v2.UniformResourceIdentifier
	for _, uriString := range uriList {
		uri, err := v2.NewURIFromString(uriString)
		if err != nil {
			r.logger.Error("provided URI could not be parsed", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid URI string in allowedURIs")
			return
		}
		parsedURIs = append(parsedURIs, uri)
	}

	parsedExpiresAt, err := strconv.ParseInt(expiresAt, 10, 64)
	if err != nil {
		r.logger.Error("expiresAt time could not be parsed", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "expiresAt must be an integer")
		return
	}

	token, err := r.authorizer.CreateServiceToken(owner, parsedURIs, parsedExpiresAt)
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with creating service token")
		return
	}

	ctx.JSON(http.StatusOK, serviceTokenRes{
		Token: token,
	})
}
