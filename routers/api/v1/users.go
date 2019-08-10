package v1

import (
	"net/http"

	"github.com/unicsmcr/hs_auth/utils/auth"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/gin-gonic/gin"
)

func (r APIV1Router) getUsers(ctx *gin.Context) {
	users, err := r.userService.GetUsers(ctx)
	if err != nil {
		r.logger.Error("could not fetch users")
		models.SendAPIError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, users)
}

func (r APIV1Router) login(ctx *gin.Context) {
	email := ctx.PostForm("email")
	if email == "" {
		r.logger.Error("email was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be provided")
		return
	}

	password := ctx.PostForm("password")
	if password == "" {
		r.logger.Error("password was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "password must be provided")
		return
	}

	user, err := r.userService.GetUserWithEmailAndPassword(ctx, email, password)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			r.logger.Error("user not found", zap.String("email", email), zap.String("password", password))
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}

	token, err := auth.NewJWT(*user, []byte(r.env.GetJWTSecret()))
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with creating authentication token")
		return
	}

	ctx.JSON(http.StatusOK, token)
}
