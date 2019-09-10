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

const passwordReplacementString = "************"
const authClaimsKeyInCtx = "auth_claims"

// AuthLevelVerifierFactory creates a middleware that checks if the user's
// auth token has the required auth level and attaches the auth claims to
// the reques context. Will return a 401 if the auth token is invalid or has
// an auth level that is too low
func (r *apiV1Router) AuthLevelVerifierFactory(level authlevels.AuthLevel) func(*gin.Context) {
	return func(ctx *gin.Context) {
		token := ctx.GetHeader(authHeaderName)
		claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
		if claims == nil || claims.TokenType != auth.Auth {
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
			ctx.Abort()
			return
		} else if claims.AuthLevel < level {
			models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to use this endpoint")
			ctx.Abort()
			return
		}
		ctx.Set(authClaimsKeyInCtx, claims)
		ctx.Next()
	}
}

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
	for i := 0; i < len(users); i++ {
		users[i].Password = passwordReplacementString
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

	user, err := r.userService.GetUserWithEmail(ctx, email)
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

	err = auth.CompareHashAndPassword(user.Password, password)
	if err != nil {
		r.logger.Warn("user not found", zap.String("email", email))
		models.SendAPIError(ctx, http.StatusUnauthorized, "user not found")
		return
	}
	user.Password = passwordReplacementString

	if !user.EmailVerified {
		r.logger.Warn("user's email not verified'", zap.String("user id", user.ID.Hex()), zap.String("email", email))
		models.SendAPIError(ctx, http.StatusUnauthorized, "user's email has not been verified")
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), 0, auth.Auth, []byte(r.env.Get(environment.JWTSecret)))
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

// GET: /api/v1/users/verify
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) Verify(ctx *gin.Context) {
	claims := extractClaimsFromCtx(ctx)

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
	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
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
	user.Password = passwordReplacementString
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

	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
		return
	}

	fieldsToUpdate := map[string]interface{}{}

	if len(name) > 0 {
		fieldsToUpdate["name"] = name
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
//           user entities.User
func (r *apiV1Router) Register(ctx *gin.Context) {
	name := ctx.PostForm("name")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if len(name) == 0 || len(email) == 0 || len(password) == 0 {
		r.logger.Warn("one of name, email or password not specified", zap.String("name", name), zap.String("email", email), zap.String("password", password))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the user's name, email and passowrd")
		return
	}

	_, err := r.userService.GetUserWithEmail(ctx, email)
	if err == nil {
		r.logger.Warn("email taken", zap.String("email", email))
		models.SendAPIError(ctx, http.StatusBadRequest, "email taken")
		return
	}

	if err != services.ErrNotFound {
		r.logger.Error("could not query for user with email", zap.String("email", email), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		return
	}

	hashedPassword, err := auth.GetHashForPassword(password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		return
	}

	user, err := r.userService.CreateUser(ctx, name, email, hashedPassword, r.cfg.BaseAuthLevel)
	if err != nil {
		r.logger.Error("could not create user",
			zap.String("name", name),
			zap.String("email", email),
			zap.Int("auth level", int(r.cfg.BaseAuthLevel)),
			zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		return
	}
	user.Password = passwordReplacementString

	// TODO: change validityDuration placeholder once token validity duration is implemented
	emailToken, err := auth.NewJWT(*user, time.Now().Unix(), 0, auth.Email, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not generate JWT token",
			zap.String("user id", user.ID.Hex()),
			zap.Bool("JWT_SECRET set", r.env.Get(environment.JWTSecret) != environment.DefaultEnvVarValue),
			zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new user")
		r.userService.DeleteUserWithEmail(ctx, email)
		return
	}
	err = r.emailService.SendEmailVerificationEmail(*user, emailToken)
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

// POST: /api/v1/users/email?token={token}
// Request:  token string
// Response: status int
//           error string
func (r *apiV1Router) VerifyEmail(ctx *gin.Context) {
	token := ctx.Query("token")
	if len(token) == 0 {
		r.logger.Warn("token not specified")
		models.SendAPIError(ctx, http.StatusBadRequest, "no token specified")
		return
	}

	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil || claims.TokenType != auth.Email {
		r.logger.Warn("invalid token", zap.String("token", token))
		models.SendAPIError(ctx, http.StatusUnauthorized, "invalid token")
		return
	}

	fieldsToUpdate := map[string]interface{}{
		"email_verified": true,
	}
	err := r.userService.UpdateUserWithID(ctx, claims.Id, fieldsToUpdate)
	if err != nil {
		r.logger.Error("could not update user", zap.String("user id", claims.Id), zap.Any("fields to udpate", fieldsToUpdate))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went with verifying user's email")
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}
