package v2

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"strconv"
)

// POST: /api/v2/users/login
// x-www-form-urlencoded
// Request:  email string
//           password string
// Response: token string
// Headers:  Authorization <- token
func (r *apiV2Router) Login(ctx *gin.Context) {
	var req struct {
		Email    string `form:"email"`
		Password string `form:"password"`
	}
	_ = ctx.Bind(&req)

	if len(req.Email) == 0 {
		r.logger.Debug("email was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "email must be provided")
		return
	}

	if len(req.Password) == 0 {
		r.logger.Debug("password was not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "password must be provided")
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, req.Email, req.Password)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("email", req.Email), zap.Error(err))
			models.SendAPIError(ctx, http.StatusUnauthorized, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	token, err := r.authorizer.CreateUserToken(user.ID, r.cfg.Auth.UserTokenLifetime+r.timeProvider.Now().Unix())
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
	var req struct {
		Name     string `form:"name"`
		Email    string `form:"email"`
		Password string `form:"password"`
	}
	_ = ctx.Bind(&req)

	if len(req.Name) == 0 || len(req.Email) == 0 || len(req.Password) == 0 {
		r.logger.Debug("one of name, email or password not specified", zap.String("name", req.Name), zap.String("email", req.Email), zap.Int("password length", len(req.Password)))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the user's name, email and password")
		return
	}

	user, err := r.userService.CreateUser(ctx, req.Name, req.Email, req.Password, r.cfg.Auth.DefaultRole)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrEmailTaken:
			r.logger.Debug("email taken", zap.String("email", req.Email), zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user with given email already exists")
		default:
			r.logger.Error("could not create user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusOK)

	if r.cfg.Auth.EmailVerificationRequired {
		verificationURIs, err := r.makeEmailVerificationURIs(*user)
		if err != nil {
			r.logger.Warn("could not create URIs for email verification", zap.Error(err))
		} else {
			err = r.emailService.SendEmailVerificationEmail(ctx, *user, verificationURIs)
			if err != nil {
				r.logger.Warn("could not send email verification email", zap.Error(err))
			}
		}
	}
}

// GET: /api/v2/users
// Response: users []entities.User
// Headers:  Authorization -> token
func (r *apiV2Router) GetUsers(ctx *gin.Context) {
	var (
		users []entities.User
		err   error
	)
	if ctx.Query("team") != "" {
		users, err = r.getTeamMembersCtxAware(ctx, ctx.Query("team"))
		if err == nil && len(users) == 0 {
			r.logger.Debug("team not found", zap.String("team id", ctx.Query("team")))
			models.SendAPIError(ctx, http.StatusNotFound, "team not found")
			return
		}
	} else {
		users, err = r.userService.GetUsers(ctx)
	}

	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		case services.ErrInvalidID:
			r.logger.Debug("invalid id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		case services.ErrUserNotInTeam:
			r.logger.Debug("user is not in a team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, getUsersRes{Users: users})
}

// GET: /api/v2/users/(:id|me)
// Response: user entities.User
// Headers:  Authorization -> token
func (r *apiV2Router) GetUser(ctx *gin.Context) {
	var (
		user *entities.User
		err  error
	)
	user, err = r.getUserCtxAware(ctx, ctx.Param("id"))
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, getUserRes{
		User: *user,
	})
}

// PUT: /api/v2/users/:id/team
// x-www-form-urlencoded
// Request:  team primitive.ObjectId
// Headers:  Authorization -> token
func (r *apiV2Router) SetTeam(ctx *gin.Context) {
	teamId := ctx.PostForm("team")
	if len(teamId) == 0 {
		r.logger.Debug("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	userId := ctx.Param("id")
	if userId == "me" {
		userIdObj, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
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

		userId = userIdObj.Hex()
	}

	err := r.teamService.AddUserWithIDToTeamWithID(ctx, userId, teamId)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("user or team id is invalid", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user or team id is invalid")
		case services.ErrNotFound:
			r.logger.Debug("user or team not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user or team with given id not found")
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user is already in a team")
		default:
			r.logger.Error("could not add user to team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// DELETE: /api/v2/users/:id/team
// x-www-form-urlencoded
// Headers:  Authorization -> token
func (r *apiV2Router) RemoveFromTeam(ctx *gin.Context) {
	userId := ctx.Param("id")
	if userId == "me" {
		userIdObj, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
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

		userId = userIdObj.Hex()
	}

	err := r.teamService.RemoveUserWithIDFromTheirTeam(ctx, userId)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("user id is invalid", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user id is invalid")
		case services.ErrNotFound:
			r.logger.Debug("user or team not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user or team with given id not found")
		case services.ErrUserNotInTeam:
			r.logger.Debug("user is not in a team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user is not in a team")
		default:
			r.logger.Error("could not add user to team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// PUT: /api/v2/users/(:id|me)/password
// x-www-form-urlencoded
// Request:  password string
// Response:
// Headers:  Authorization -> token
func (r *apiV2Router) SetPassword(ctx *gin.Context) {
	var req struct {
		Password string `form:"password"`
	}
	_ = ctx.Bind(&req)
	if len(req.Password) == 0 {
		r.logger.Debug("password not specified", zap.Int("password length", len(req.Password)))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the new password")
		return
	}

	userId := ctx.Param("id")
	if userId == "me" {
		userIdObj, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
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
		userId = userIdObj.Hex()
	}

	pwdHash, err := auth.GetHashForPassword(req.Password)
	if err != nil {
		r.logger.Error("failed to hash password", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, userId, services.UserUpdateParams{
		entities.UserPassword: pwdHash,
	})
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user does not exist")
		default:
			r.logger.Error("could not update user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// GET: /api/v2/users/(:id|me)/password/resetEmail
// Response:
// Headers:  Authorization -> token
func (r *apiV2Router) GetPasswordResetEmail(ctx *gin.Context) {
	_, err := r.getUserCtxAware(ctx, ctx.Param("id"))
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	// TODO: Update email service to use Auth V2 (see https://github.com/unicsmcr/hs_auth/issues/107)
	//err = r.emailService.SendPasswordResetEmail(*user)
	//if err != nil {
	//	r.logger.Error("could not send password reset email", zap.Error(err))
	//	models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
	//}

	ctx.Status(http.StatusOK)
}

// PUT: /api/v2/users/:id/role
// x-www-form-urlencoded
// Request:  role string
// Headers:  Authorization -> token
func (r *apiV2Router) SetRole(ctx *gin.Context) {
	var err error

	roleReq := ctx.PostForm("role")
	if len(roleReq) == 0 {
		r.logger.Debug("role not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "user role must be provided")
		return
	}

	var userRole role.UserRole
	err = json.Unmarshal([]byte(strconv.Quote(roleReq)), &userRole)
	if err != nil {
		r.logger.Debug("invalid role", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "role does not exist")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, ctx.Param("id"), services.UserUpdateParams{
		entities.UserRole: userRole,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id provided")
		case services.ErrNotFound:
			r.logger.Debug("user not found")
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem when updating the user")
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// PUT: /api/v2/users/:id/permissions
// x-www-form-urlencoded
// Request:  permissions string
// Headers:  Authorization -> token
func (r *apiV2Router) SetSpecialPermissions(ctx *gin.Context) {
	var (
		err error
		req struct {
			Permissions string `form:"permissions"`
		}
	)
	_ = ctx.Bind(&req)
	if len(req.Permissions) == 0 {
		r.logger.Debug("could not parse special user permissions request", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "failed to parse permissions in request")
		return
	}

	var parsedURIs common.UniformResourceIdentifiers
	err = json.Unmarshal([]byte(req.Permissions), &parsedURIs)
	if err != nil {
		r.logger.Debug("provided URI could not be parsed", zap.Error(err))
		models.SendAPIError(ctx, http.StatusBadRequest, "invalid URI string in permissions")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, ctx.Param("id"), services.UserUpdateParams{
		entities.UserSpecialPermissions: parsedURIs,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id provided")
		case services.ErrNotFound:
			r.logger.Debug("user not found")
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem when updating the user")
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// PUT: /api/v2/users/(:id|me)/email/verify
// x-www-form-urlencoded
// Headers:  Authorization -> token
func (r *apiV2Router) VerifyEmail(ctx *gin.Context) {
	err := r.userService.UpdateUserWithID(ctx, ctx.Param("id"), services.UserUpdateParams{
		entities.UserRole: r.cfg.Auth.DefaultEmailVerifiedRole,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id provided")
		case services.ErrNotFound:
			r.logger.Debug("user not found")
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.Status(http.StatusNoContent)

	err = r.authorizer.InvalidateServiceToken(ctx, r.GetAuthToken(ctx))
	if err != nil {
		r.logger.Warn("could not invalidate token after email verification", zap.Error(err))
	}
}

// GET: /api/v2/users/(:id|me)/email/verify
// Headers:  Authorization -> token
func (r *apiV2Router) ResendEmailVerification(ctx *gin.Context) {
	user, err := r.getUserCtxAware(ctx, ctx.Param("id"))
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "user not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	verificationURIs, err := r.makeEmailVerificationURIs(*user)
	if err != nil {
		r.logger.Error("could create email verification URIs", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = r.emailService.SendEmailVerificationEmail(ctx, *user, verificationURIs)
	if err != nil {
		r.logger.Error("could send email verification email", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.Status(http.StatusNoContent)
}

// getUserCtxAware fetches user with the given id. If id is "me", getUserCtxAware tries to extract the user from the ctx
func (r *apiV2Router) getUserCtxAware(ctx *gin.Context, userId string) (*entities.User, error) {
	if userId == "me" {
		token := r.GetAuthToken(ctx)
		userIdObj, err := r.authorizer.GetUserIdFromToken(token)
		if err != nil {
			return nil, errors.Wrap(err, "could not extract user id from auth token")
		}

		userId = userIdObj.Hex()
	}

	user, err := r.userService.GetUserWithID(ctx, userId)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch user")
	}

	return user, nil
}

// getTeamMembersCtxAware fetches team members for team with the given id.
// If id is "me", getTeamMembersCtxAware tries to extract the team from the ctx
func (r *apiV2Router) getTeamMembersCtxAware(ctx *gin.Context, teamId string) ([]entities.User, error) {
	var (
		members []entities.User
		err     error
	)
	if teamId == "me" {
		token := r.GetAuthToken(ctx)
		var userIdObj primitive.ObjectID
		userIdObj, err = r.authorizer.GetUserIdFromToken(token)
		if err != nil {
			return nil, errors.Wrap(err, "could not extract user id from auth token")
		}

		members, err = r.userService.GetTeamMembersForUserWithID(ctx, userIdObj.Hex())
	} else {
		members, err = r.userService.GetUsersWithTeam(ctx, teamId)
	}

	if err != nil {
		return nil, errors.Wrap(err, "could not fetch team members")
	}

	return members, nil
}

func (r *apiV2Router) makeEmailVerificationURIs(user entities.User) (common.UniformResourceIdentifiers, error) {
	apiUri, err := common.NewURIFromString(fmt.Sprintf("%s:VerifyEmail?path_id=%s", r.GetResourcePath(), user.ID.Hex()))
	if err != nil {
		return nil, errors.Wrap(err, "could not create URI for API email verification resource")
	}

	// TODO: add resource for frontend email verification (https://github.com/unicsmcr/hs_auth/issues/106)
	return []common.UniformResourceIdentifier{apiUri}, err
}
