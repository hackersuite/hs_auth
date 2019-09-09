package v1

import (
	"net/http"
	"time"

	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/gin-gonic/gin"
)

// GET: /api/v1/users/
// Response: status int
//           error string
//           users []entities.User
func (r *apiV1Router) GetUsers(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil {
		models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
		return
	} else if claims.AuthLevel < authlevels.Organizer {
		models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this endpoint")
		return
	}

	users, err := r.userService.GetUsers(ctx)
	if err != nil {
		r.logger.Error("could not fetch users", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, getUsersRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: users,
	})
}

// POST: /api/v1/users/login
// x-www-form-urlencoded
// Request:  email string
//           password string
// Response: token string
//           status int
//           error string
// Headers:  Authorization <- token
func (r *apiV1Router) Login(ctx *gin.Context) {
	email := ctx.PostForm("email")
	if email == "" {
		r.logger.Warn("email was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be provided")
		return
	}

	password := ctx.PostForm("password")
	if password == "" {
		r.logger.Warn("password was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "password must be provided")
		return
	}

	user, err := r.userService.GetUserWithEmailAndPassword(ctx, email, password)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.Any("user", *user), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with creating authentication token")
		return
	}

	ctx.Header("Authorization", token)
	ctx.JSON(http.StatusOK, loginRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Token: token,
		User:  *user,
	})
}

// GET: /api/v1/users/verify
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) Verify(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil {
		models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
		return
	}

	r.logger.Info("claims", zap.Any("claims", claims))
	ctx.JSON(http.StatusOK, verifyRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
	})
}

// GET: /api/v1/users/me
// Response: status int
//           error string
//           user entities.User
// Headers:  Authorization -> token
func (r *apiV1Router) GetMe(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil {
		r.logger.Warn("invalid token", zap.String("token", token))
		models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.Any("id", claims.Id))
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}
	ctx.JSON(http.StatusOK, getMeRes{
		User: *user,
	})
}

// PUT: /api/v1/users/me
// x-www-form-urlencoded
// Request:  name string
//           team primitive.ObjectID.Hex
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) PutMe(ctx *gin.Context) {
	name := ctx.PostForm("name")
	team := ctx.PostForm("team")

	if len(name) == 0 && len(team) == 0 {
		r.logger.Warn("neither name nor team provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "either name or team must be provided")
		return
	}

	token := ctx.GetHeader("Authorization")
	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil {
		models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
		return
	}

	fieldsToUpdate := map[string]interface{}{}

	if len(name) > 0 {
		fieldsToUpdate["name"] = name
	}
	if len(team) > 0 {
		// TODO: check if team exists (need to implement teams persistence first)
		fieldsToUpdate["team"] = team
	}

	err := r.userService.UpdateUserWithID(ctx, claims.Id, fieldsToUpdate)
	if err != nil {
		r.logger.Error("could not update user", zap.String("id", claims.Id), zap.Any("fields to update", fieldsToUpdate), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with updating the user")
		return
	}
	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// POST: /api/v1/users
// x-www-form-urlencoded
// Request:  name string
//           email string
//					 password string
// Response: status int
//           error string
func (r *apiV1Router) Register(ctx *gin.Context) {
	name := ctx.PostForm("name")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if len(name) == 0 || len(email) == 0 || len(password) == 0 {
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the user's name, email and passowrd")
		return
	}

	_, err := r.userService.CreateUser(ctx, name, email, password, r.cfg.BaseAuthLevel)
	if err != nil {
		r.logger.Error("could not create user", zap.String("name", name), zap.String("email", email), zap.Int("auth level", int(r.cfg.BaseAuthLevel)))
		return
	}

	// TODO: implement email verification

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}
