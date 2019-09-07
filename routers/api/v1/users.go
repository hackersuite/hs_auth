package v1

import (
	"net/http"
	"time"

	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/gin-gonic/gin"
)

// GET: /api/v1/users/
// Response: status int
//           error string
//           users []entities.User

func (r *apiV1Router) GetUsers(ctx *gin.Context) {
	users, err := r.userService.GetUsers(ctx)
	if err != nil {
		r.logger.Error("could not fetch users")
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

	token, err := auth.NewJWT(*user, time.Now().Unix(), []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
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
// Response: user entities.User
// Headers:  Authorization -> token
func (r *apiV1Router) GetMe(ctx *gin.Context) {

}

// PUT: /api/v1/users/me
// Request: name string
//          team primitive.ObjectID
// Headers: Authorization -> token
func (r *apiV1Router) PutMe(ctx *gin.Context) {

}
