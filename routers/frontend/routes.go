package frontend

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/common"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils"
	"go.uber.org/zap"
	"net/http"
)

const returnToCookie = "ReturnTo"

func (r *frontendRouter) RedirectToEntryPage(ctx *gin.Context) {
	if len(r.GetAuthToken(ctx)) != 0 {
		ctx.Redirect(http.StatusPermanentRedirect, "/profile")
	} else {
		ctx.Redirect(http.StatusPermanentRedirect, "/login")
	}
}

func (r *frontendRouter) ProfilePage(ctx *gin.Context) {
	r.renderPage(ctx, profilePage, http.StatusOK, nil, "")
}

func (r *frontendRouter) LoginPage(ctx *gin.Context) {
	returnTo := ctx.Query("returnto")
	if len(returnTo) > 0 {
		ctx.SetCookie(returnToCookie, returnTo, 100, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	}

	r.renderPage(ctx, loginPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) Login(ctx *gin.Context) {
	var req struct {
		Email    string `form:"email"`
		Password string `form:"password"`
	}
	ctx.Bind(&req)
	if len(req.Email) == 0 || len(req.Password) == 0 {
		r.logger.Debug("email or password was not provided", zap.Int("email length", len(req.Email)),
			zap.Int("password length", len(req.Password)))
		r.renderPage(ctx, loginPage, http.StatusBadRequest, nil, "Both email and password are required")
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, req.Email, req.Password)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("email", req.Email), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusNotFound, nil, "User not found")
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	token, err := r.authorizer.CreateUserToken(user.ID, r.cfg.Auth.UserTokenLifetime+r.timeProvider.Now().Unix())
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		return
	}

	ctx.SetCookie(authCookieName, token, int(r.cfg.Auth.UserTokenLifetime), "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)

	if user.Role == role.Unverified {
		r.logger.Debug("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", req.Email))
		ctx.Redirect(http.StatusMovedPermanently, "/emailunverified")
		return
	}

	returnTo, err := ctx.Cookie(returnToCookie)
	if err != nil && len(returnTo) == 0 {
		returnTo = "/"
	}
	ctx.SetCookie(returnToCookie, returnTo, -1, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	ctx.Redirect(http.StatusMovedPermanently, returnTo)
}

func (r *frontendRouter) RegisterPage(ctx *gin.Context) {
	r.renderPage(ctx, registerPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) Register(ctx *gin.Context) {
	var req struct {
		Name            string `form:"name"`
		Email           string `form:"email"`
		Password        string `form:"password"`
		PasswordConfirm string `form:"passwordConfirm"`
	}
	ctx.Bind(&req)

	if len(req.Name) == 0 || len(req.Email) == 0 || len(req.Password) == 0 {
		r.logger.Debug("one of name, email, password, passwordConfirm not specified", zap.String("name", req.Name), zap.String("email", req.Email), zap.Int("password length", len(req.Password)), zap.Int("passwordConfirm length", len(req.PasswordConfirm)))
		r.renderPage(ctx, registerPage, http.StatusBadRequest, nil, "All fields are required")
		return
	}

	// TODO: implement automatic validation at the entity level (https://github.com/unicsmcr/hs_auth/issues/123)
	if len(req.Password) < 6 || len(req.Password) > 160 {
		r.logger.Debug("invalid password length", zap.Int("length", len(req.Password)))
		r.renderPage(ctx, registerPage, http.StatusBadRequest, nil, "Password must contain between 6 and 160 characters")
		return
	}

	if req.Password != req.PasswordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		r.renderPage(ctx, registerPage, http.StatusBadRequest, nil, "Passwords do not match")
		return
	}

	user, err := r.userService.CreateUser(ctx, req.Name, req.Email, req.Password, r.cfg.Auth.DefaultRole)
	if err != nil {
		switch err {
		case services.ErrEmailTaken:
			r.logger.Debug("email taken")
			r.renderPage(ctx, registerPage, http.StatusBadRequest, nil, "Email taken")
			return
		default:
			r.logger.Error("could not create user", zap.Error(err))
			r.renderPage(ctx, registerPage, http.StatusInternalServerError, nil, "Something went wrong")
			return
		}
	}

	type registerEndPageData struct {
		Email string
	}
	r.renderPage(ctx, registerEndPage, http.StatusOK, registerEndPageData{
		Email: user.Email,
	}, "")

	err = r.emailServiceV2.SendEmailVerificationEmail(ctx, *user, common.MakeEmailVerificationURIs(*user))
	if err != nil {
		r.logger.Error("could not send email verification email", zap.Error(err))
	}
}

func (r *frontendRouter) ForgotPasswordPage(ctx *gin.Context) {
	r.renderPage(ctx, forgotPasswordPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) ForgotPassword(ctx *gin.Context) {
	email := ctx.PostForm("email")

	if len(email) == 0 {
		r.logger.Debug("email not specified")
		r.renderPage(ctx, forgotPasswordPage, http.StatusBadRequest, nil, "Please enter your email")
		return
	}

	type res struct {
		Email string
	}
	user, err := r.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user with email doesn't exist", zap.String("email", email))
			r.renderPage(ctx, forgotPasswordEndPage, http.StatusOK, res{Email: email}, "")
		default:
			r.logger.Error("could not fetch user", zap.String("email", email), zap.Error(err))
			r.renderPage(ctx, forgotPasswordPage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	err = r.emailServiceV2.SendPasswordResetEmail(ctx, *user, common.MakePasswordResetURIs(*user))
	if err != nil {
		r.logger.Error("could not send password reset email", zap.Error(err))
		r.renderPage(ctx, forgotPasswordPage, http.StatusInternalServerError, nil, "Something went wrong")
		return
	}

	r.renderPage(ctx, forgotPasswordEndPage, http.StatusOK, res{Email: email}, "")
}

func (r *frontendRouter) ResetPasswordPage(ctx *gin.Context) {
	ctx.SetCookie(authCookieName, ctx.Query("token"), int(r.cfg.Auth.UserTokenLifetime), "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)

	type res struct {
		UserId string
	}
	r.renderPage(ctx, resetPasswordPage, http.StatusOK, res{UserId: ctx.Query("userId")}, "")
}

func (r *frontendRouter) ResetPassword(ctx *gin.Context) {
	var req struct {
		UserId          string `form:"userId"`
		Password        string `form:"password"`
		PasswordConfirm string `form:"passwordConfirm"`
	}
	ctx.Bind(&req)

	type res struct {
		UserId string
	}
	if len(req.Password) == 0 {
		r.logger.Debug("password not specified", zap.Int("password len", len(req.Password)))
		r.renderPage(ctx, resetPasswordPage, http.StatusBadRequest, res{UserId: req.UserId}, "All fields are required")
		return
	}

	if req.Password != req.PasswordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		r.renderPage(ctx, resetPasswordPage, http.StatusBadRequest, res{UserId: req.UserId}, "Passwords do not match")
		return
	}

	hashedPassword, err := utils.GetHashForPassword(req.Password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		r.renderPage(ctx, resetPasswordPage, http.StatusInternalServerError, res{UserId: req.UserId}, "Something went wrong")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, req.UserId, services.UserUpdateParams{
		entities.UserPassword: hashedPassword,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.String("user id", req.UserId), zap.Error(err))
			r.renderPage(ctx, resetPasswordPage, http.StatusBadRequest, res{UserId: req.UserId}, "Invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			r.renderPage(ctx, resetPasswordPage, http.StatusNotFound, res{UserId: req.UserId}, "User not found")
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			r.renderPage(ctx, resetPasswordPage, http.StatusInternalServerError, res{UserId: req.UserId}, "Something went wrong")
		}
		return
	}

	err = r.authorizer.InvalidateServiceToken(ctx, r.GetAuthToken(ctx))
	if err != nil {
		r.logger.Warn("could not invalidate service token", zap.Error(err))
	}

	ctx.SetCookie(authCookieName, "", 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	r.renderPage(ctx, resetPasswordEndPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) VerifyEmail(ctx *gin.Context) {
	userId := ctx.Query("userId")
	user, err := r.userService.GetUserWithID(ctx, userId)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.String("userId", userId), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusBadRequest, nil, "Invalid user id")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("userId", userId), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusNotFound, nil, "User not found")
		default:
			r.logger.Debug("could not fetch user", zap.String("userId", userId), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	if user.Role != role.Unverified {
		r.logger.Debug("user's email is already verified", zap.String("userId", userId))
		r.renderPage(ctx, loginPage, http.StatusBadRequest, nil, "Your email is already verified")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, userId, services.UserUpdateParams{
		entities.UserRole: r.cfg.Auth.DefaultEmailVerifiedRole,
	})
	if err != nil {
		r.logger.Debug("could not update user", zap.String("userId", userId), zap.Error(err))
		r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		return
	}

	r.renderPage(ctx, verifyEmailPage, http.StatusOK, nil, "")

	err = r.authorizer.InvalidateServiceToken(ctx, ctx.Query("token"))
	if err != nil {
		r.logger.Warn("could not invalidate service token", zap.Error(err))
	}
}

func (r *frontendRouter) Logout(ctx *gin.Context) {
	ctx.SetCookie(authCookieName, "", 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	r.renderPage(ctx, loginPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) CreateTeam(ctx *gin.Context) {
	name := ctx.PostForm("name")
	if len(name) == 0 {
		r.logger.Debug("team name not specified", zap.String("name", name))
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Please specify team name")
		return
	}

	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		switch errors.Cause(err) {
		case authCommon.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not extract user id from token", zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	_, err = r.teamService.CreateTeamForUserWithID(ctx, name, userId.Hex())
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNameTaken:
			r.logger.Debug("team name taken", zap.String("teamName", name), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Team with the given name already exists")
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in team", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "You are already in a team")
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusNotFound, nil, "User not found")
		default:
			r.logger.Error("could not create team for user", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	r.renderPage(ctx, profilePage, http.StatusOK, nil, "")
}

func (r *frontendRouter) JoinTeam(ctx *gin.Context) {
	teamId := ctx.PostForm("id")
	if len(teamId) == 0 {
		r.logger.Debug("team id not provided")
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Please specify the ID of the team to join")
		return
	}

	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		switch errors.Cause(err) {
		case authCommon.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not extract user id from token", zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	err = r.teamService.AddUserWithIDToTeamWithID(ctx, userId.Hex(), teamId)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("invalid team id", zap.String("teamId", teamId), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Invalid team ID provided")
		case services.ErrNotFound:
			r.logger.Debug("team not found", zap.String("teamId", teamId), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusNotFound, nil, "Team with given ID does not exist")
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in team", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "You are already in a team")
		default:
			r.logger.Debug("could not add user to team", zap.String("userId", userId.Hex()), zap.String("teamId", teamId), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	r.renderPage(ctx, profilePage, http.StatusOK, nil, "")
}

func (r *frontendRouter) LeaveTeam(ctx *gin.Context) {
	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		switch errors.Cause(err) {
		case authCommon.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not extract user id from token", zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	err = r.teamService.RemoveUserWithIDFromTheirTeam(ctx, userId.Hex())
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusNotFound, nil, "User not found")
		case services.ErrUserNotInTeam:
			r.logger.Debug("user is not in a team", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "You are not in a team")
		default:
			r.logger.Debug("could not remove user from team", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	r.renderPage(ctx, profilePage, http.StatusOK, nil, "")
}

func (r *frontendRouter) UpdateUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if len(userID) == 0 {
		r.logger.Debug("user id not provided")
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "User ID not provided")
		return
	}

	var updatedFields map[entities.UserField]string
	err := json.Unmarshal([]byte(ctx.PostForm("set")), &updatedFields)

	if err != nil {
		r.logger.Debug("could not unmarshal params to update", zap.Error(err))
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Invalid parameters to update")
		return
	}
	// TODO: input validation should be done at the service level
	builtParams, err := services.BuildUserUpdateParams(r.cfg, updatedFields)
	if err != nil {
		r.logger.Debug("could not build params to update", zap.Error(err))
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Invalid parameters to update")
		return
	}

	if _, exists := builtParams[entities.UserPassword]; exists {
		r.logger.Debug("user's password cannot be updated")
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "User's password cannot be changed")
		return
	}

	if _, exists := builtParams[entities.UserID]; exists {
		r.logger.Debug("user's id cannot be updated")
		r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "User's id cannot be changed")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, userID, builtParams)
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id")
			r.renderPage(ctx, profilePage, http.StatusBadRequest, nil, "Invalid user id provided")
			break
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			r.renderPage(ctx, profilePage, http.StatusInternalServerError, nil, "Something went wrong")
			break
		}
		return
	}

	r.renderPage(ctx, profilePage, http.StatusOK, nil, "")
}

func (r *frontendRouter) EmailUnverifiedPage(ctx *gin.Context) {
	r.renderPage(ctx, emailUnverifiedPage, http.StatusOK, nil, "")
}

func (r *frontendRouter) VerifyEmailResend(ctx *gin.Context) {
	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		switch errors.Cause(err) {
		case authCommon.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not extract token type", zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	user, err := r.userService.GetUserWithID(ctx, userId.Hex())
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusNotFound, nil, "User not found")
		default:
			r.logger.Debug("could not fetch user", zap.String("userId", userId.Hex()), zap.Error(err))
			r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		}
		return
	}

	err = r.emailServiceV2.SendEmailVerificationEmail(ctx, *user, common.MakeEmailVerificationURIs(*user))
	if err != nil {
		r.logger.Debug("could not send email verification email", zap.Error(err))
		r.renderPage(ctx, loginPage, http.StatusInternalServerError, nil, "Something went wrong")
		return
	}

	r.renderPage(ctx, verifyEmailResendPage, http.StatusOK, nil, "")
}
