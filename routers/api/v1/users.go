package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.uber.org/zap"
)

// GET: /api/v1/users/
// Response: status int
//           error string
//           users []entities.User
func (r *apiV1Router) GetUsers(ctx *gin.Context) {
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

// PUT: /api/v1/users/{id}
// x-www-form-urlencoded
// Request:  set map[entities.UserField]interface{}
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) UpdateUser(ctx *gin.Context) {

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

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, email, password)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
			models.SendAPIError(ctx, http.StatusUnauthorized, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), r.cfg.AuthTokenLifetime, auth.Auth, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.String("user", user.ID.Hex()), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with creating authentication token")
		return
	}

	ctx.Header(authHeaderName, token)
	ctx.JSON(http.StatusOK, loginRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Token: token,
		User:  *user,
	})
}

// GET: /api/v1/users/me
// Response: status int
//           error string
//           user entities.User
// Headers:  Authorization -> token
func (r *apiV1Router) GetMe(ctx *gin.Context) {
	user, err := r.userService.GetUserWithJWT(ctx, ctx.GetHeader(authHeaderName))
	if err != nil {
		if err == services.ErrInvalidToken {
			r.logger.Warn("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
		} else if err == services.ErrNotFound {
			r.logger.Warn("user not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}
	ctx.JSON(http.StatusOK, getMeRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
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

	fieldsToUpdate := services.UserUpdateParams{}

	if len(name) > 0 {
		fieldsToUpdate[entities.UserName] = name
	}
	if len(team) > 0 {
		_, err := r.teamService.GetTeamWithID(ctx, team)
		if err != nil {
			if err == services.ErrInvalidID {
				r.logger.Warn("invalid team id", zap.String("id", team))
				models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id")
				return
			} else if err == services.ErrNotFound {
				r.logger.Warn("team with given id doesn't exist", zap.String("id", team))
				models.SendAPIError(ctx, http.StatusBadRequest, "could not find team with given id")
				return
			} else {
				r.logger.Error("could not fetch team with id", zap.String("id", team), zap.Error(err))
				models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
				return
			}
		}
		fieldsToUpdate[entities.UserTeam] = team
	}

	err := r.userService.UpdateUserWithJWT(ctx, ctx.GetHeader(authHeaderName), fieldsToUpdate)
	if err != nil {
		if err == services.ErrInvalidToken {
			r.logger.Warn("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
		} else {
			r.logger.Error("could not update user", zap.Any("fields to update", fieldsToUpdate), zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with updating the user")
		}
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
//           user entities.User
func (r *apiV1Router) Register(ctx *gin.Context) {
	name := ctx.PostForm("name")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if len(name) == 0 || len(email) == 0 || len(password) == 0 {
		r.logger.Warn("one of name, email or password not specified", zap.String("name", name), zap.String("email", email), zap.Int("password length", len(password)))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the user's name, email and passowrd")
		return
	}

	user, err := r.userService.CreateUser(ctx, name, email, password)
	if err == services.ErrEmailTaken {
		r.logger.Warn("email taken", zap.String("email", email))
		models.SendAPIError(ctx, http.StatusBadRequest, "user with given email already exists")
		return
	} else if err != nil {
		r.logger.Error("could not create user", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		return
	}

	err = r.emailService.SendEmailVerificationEmail(*user)
	if err != nil {
		r.logger.Error("could not send email verification email",
			zap.String("user email", user.Email),
			zap.String("noreply email", r.cfg.Email.NoreplyEmailAddr),
			zap.Bool("SENDGRID_API_KEY set", r.env.Get(environment.SendgridAPIKey) != environment.DefaultEnvVarValue),
			zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		r.userService.DeleteUserWithEmail(ctx, email)
		return
	}

	ctx.JSON(http.StatusOK, registerRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		User: *user,
	})
}

// POST: /api/v1/users/email
// Response: status int
//           error string
// Header:   Authorization -> token
func (r *apiV1Router) VerifyEmail(ctx *gin.Context) {
	// TODO: this should increase user's auth level
	fieldsToUpdate := services.UserUpdateParams{
		entities.UserEmailVerified: true,
	}
	err := r.userService.UpdateUserWithJWT(ctx, ctx.GetHeader(authHeaderName), fieldsToUpdate)
	if err != nil {
		if err == services.ErrInvalidToken {
			r.logger.Warn("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
		} else {
			r.logger.Error("could not update user", zap.Any("fields to udpate", fieldsToUpdate))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// GET: /api/v1/users/password/reset?email={email}
// Request:  email string
// Response: status int
//           error string
func (r *apiV1Router) GetPasswordResetEmail(ctx *gin.Context) {
	email := ctx.Query("email")
	if len(email) == 0 {
		r.logger.Warn("email not specified")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be specified")
		return
	}

	err := r.emailService.SendPasswordResetEmailForUserWithEmail(ctx, email)
	if err != nil {
		r.logger.Error("could not send password reset email", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// PUT: /api/v1/users/password/reset?email={email}
// Request:  email string
//           password string (x-www-form-urlencoded)
// Response: status int
//           error string
// Header:   Authorization -> token
func (r *apiV1Router) ResetPassword(ctx *gin.Context) {
	email := ctx.Query("email")
	if len(email) == 0 {
		r.logger.Warn("email not specified")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be specified")
		return
	}

	password := ctx.PostForm("password")
	if len(password) == 0 {
		r.logger.Warn("password not specified")
		models.SendAPIError(ctx, http.StatusBadRequest, "password must be specified")
		return
	}

	err := r.userService.ResetPasswordForUserWithJWTAndEmail(ctx, ctx.GetHeader(authHeaderName), email, password)
	if err != nil {
		if err == services.ErrInvalidToken {
			r.logger.Warn("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
		}
		r.logger.Error("could not set user's password", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// GET: /api/v1/users/teammates
// Response: status int
//           error string
//           users []entities.User
// Headers:  Authorization -> token
func (r *apiV1Router) GetTeammates(ctx *gin.Context) {
	teammates, err := r.userService.GetTeammatesForUserWithJWT(ctx, ctx.GetHeader(authHeaderName))
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Warn("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
			break
		case services.ErrInvalidID:
			r.logger.Warn("invalid user id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id provided")
			break
		case services.ErrNotFound:
			r.logger.Warn("user not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
			break
		case services.ErrUserNotInTeam:
			r.logger.Warn("user is not in a team")
			models.SendAPIError(ctx, http.StatusBadRequest, "user is not in a team")
			break
		default:
			r.logger.Error("could fetch user's teammates", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with finding user's teammates")
			break
		}
		return
	}

	ctx.JSON(http.StatusOK, getTeammatesRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: teammates,
	})
}
