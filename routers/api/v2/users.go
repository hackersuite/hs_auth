package v2

import (
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
	"net/http"
)

// POST: /api/v2/users/login
// x-www-form-urlencoded
// Request:  email string
//           password string
// Response: token string
// Headers:  Authorization <- token
func (r *apiV2Router) Login(ctx *gin.Context) {
	email := ctx.PostForm("email")
	if len(email) == 0 {
		r.logger.Debug("email was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be provided")
		return
	}

	password := ctx.PostForm("password")
	if len(password) == 0 {
		r.logger.Debug("password was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "password must be provided")
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, email, password)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("email", email), zap.Error(err))
			models.SendAPIError(ctx, http.StatusUnauthorized, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	token, err := r.authorizer.CreateUserToken(user.ID, r.cfg.AuthTokenLifetime+r.timeProvider.Now().Unix())
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.Header(authTokenHeader, token)
	ctx.JSON(http.StatusOK, loginRes{
		Token: token,
	})
}

// POST: /api/v2/users
// x-www-form-urlencoded
// Request:  name string
//           email string
//           password string
// Response:
func (r *apiV2Router) Register(ctx *gin.Context) {
	name := ctx.PostForm("name")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if len(name) == 0 || len(email) == 0 || len(password) == 0 {
		r.logger.Debug("one of name, email or password not specified", zap.String("name", name), zap.String("email", email), zap.Int("password length", len(password)))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the user's name, email and passowrd")
		return
	}

	_, err := r.userService.CreateUser(ctx, name, email, password)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrEmailTaken:
			r.logger.Debug("email taken", zap.String("email", email), zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user with given email already exists")
		default:
			r.logger.Error("could not create user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	// TODO: add email verification (https://github.com/unicsmcr/hs_auth/issues/87)

	ctx.Status(http.StatusOK)
}
