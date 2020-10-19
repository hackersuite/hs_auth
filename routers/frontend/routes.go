package frontend

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/routers/common"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
)

const ReturnToCookie = "ReturnTo"

type profilePageData struct {
	User      *entities.User
	Team      *entities.Team
	Teammates []entities.User
	AdminData adminData
}

type adminData struct {
	Users []entities.User `json:"users"`
}

func (r *frontendRouter) renderProfilePage(ctx *gin.Context, statusCode int, error string) {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Invalid auth token",
		})
		return
	}

	userInfo, routerErr := r.getProfilePageData(ctx, jwt)
	if routerErr != nil {
		r.logger.Error("could not fetch basic user info", zap.Error(routerErr))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	returnTo, cookieErr := ctx.Cookie("ReturnTo")
	if cookieErr == nil {
		ctx.HTML(statusCode, "profile.gohtml", templateDataModel{
			Cfg:      r.cfg,
			Data:     userInfo,
			Err:      error,
			ReturnTo: returnTo,
		})
	} else {
		ctx.HTML(statusCode, "profile.gohtml", templateDataModel{
			Cfg:  r.cfg,
			Data: userInfo,
			Err:  error,
		})
	}
}

func (r *frontendRouter) getProfilePageData(ctx *gin.Context, jwt string) (profilePageData, error) {
	var data profilePageData
	var err error
	data.User, err = r.userService.GetUserWithJWT(ctx, jwt)
	if err != nil {
		return profilePageData{}, err
	}

	if data.User.AuthLevel >= authlevels.Organiser {
		users, err := r.userService.GetUsers(ctx)
		if err != nil {
			r.logger.Error("could not get users", zap.Error(err))
			return data, nil
		}
		data.AdminData.Users = users
	}

	data.Team, data.Teammates, err = r.getUserTeamInfo(ctx, data.User)
	if err != nil {
		r.logger.Error("could not get information about user's team", zap.Error(err))
		return data, nil
	}

	return data, nil
}

func (r *frontendRouter) getUserTeamInfo(ctx *gin.Context, user *entities.User) (team *entities.Team, teammates []entities.User, err error) {
	if user.Team == primitive.NilObjectID {
		return nil, nil, nil
	}

	team, err = r.teamService.GetTeamWithID(ctx, user.Team.Hex())
	if err != nil {
		r.logger.Error("could not get user's team", zap.Error(err))
		return nil, nil, err
	}
	teammates, err = r.userService.GetTeammatesForUserWithID(ctx, user.ID.Hex())
	if err != nil {
		r.logger.Error("could not get user's teammates", zap.Error(err))
		return team, nil, err
	}
	return team, teammates, nil
}

func (r *frontendRouter) ProfilePage(ctx *gin.Context) {
	r.renderProfilePage(ctx, http.StatusOK, "")
}

func (r *frontendRouter) LoginPage(ctx *gin.Context) {
	returnTo := ctx.Query("returnto")
	if len(returnTo) > 0 {
		ctx.SetCookie(ReturnToCookie, returnTo, 100, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	}

	ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
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
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Both email and password are required",
		})
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, req.Email, req.Password)
	if err != nil {
		switch errors.Cause(err) {
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.String("email", req.Email), zap.Error(err))
			ctx.HTML(http.StatusNotFound, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "User not found",
			})
		default:
			r.logger.Error("could not fetch user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
		}
		return
	}

	token, err := r.authorizer.CreateUserToken(user.ID, r.cfg.Auth.UserTokenLifetime+r.timeProvider.Now().Unix())
	if err != nil {
		r.logger.Error("could not create JWT", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	ctx.SetCookie(authCookieName, token, int(r.cfg.Auth.UserTokenLifetime), "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)

	if user.Role == role.Unverified {
		r.logger.Debug("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", req.Email))
		ctx.Redirect(http.StatusMovedPermanently, "/emailunverified")
		return
	}

	returnTo, err := ctx.Cookie(ReturnToCookie)
	if err != nil && len(returnTo) == 0 {
		returnTo = "/"
	}
	ctx.SetCookie(ReturnToCookie, returnTo, 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	ctx.Redirect(http.StatusMovedPermanently, returnTo)
}

func (r *frontendRouter) RegisterPage(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "register.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
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
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "All fields are required",
		})
		return
	}

	// TODO: implement automatic validation at the entity level (https://github.com/unicsmcr/hs_auth/issues/123)
	if len(req.Password) < 6 || len(req.Password) > 160 {
		r.logger.Debug("invalid password length", zap.Int("length", len(req.Password)))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Password must contain between 6 and 160 characters",
		})
		return
	}

	if req.Password != req.PasswordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Passwords do not match",
		})
		return
	}

	user, err := r.userService.CreateUser(ctx, req.Name, req.Email, req.Password, r.cfg.Auth.DefaultRole)
	if err != nil {
		switch err {
		case services.ErrEmailTaken:
			r.logger.Debug("email taken")
			ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Email taken",
			})
			return
		default:
			r.logger.Error("could not create user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
			return
		}
	}

	type res struct {
		Email string
	}
	ctx.HTML(http.StatusOK, "registerEnd.gohtml", templateDataModel{
		Cfg: r.cfg,
		Data: res{
			Email: user.Email,
		},
	})

	err = r.emailServiceV2.SendEmailVerificationEmail(ctx, *user, common.MakeEmailVerificationURIs(*user))
	if err != nil {
		r.logger.Error("could not send email verification email", zap.Error(err))
	}
}

func (r *frontendRouter) ForgotPasswordPage(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "forgotPassword.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) ForgotPassword(ctx *gin.Context) {
	email := ctx.PostForm("email")

	if len(email) == 0 {
		r.logger.Debug("email not specified")
		ctx.HTML(http.StatusBadRequest, "forgotPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Please enter your email",
		})
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
			ctx.HTML(http.StatusOK, "forgotPasswordEnd.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: res{
					Email: email,
				},
			})
		default:
			r.logger.Error("could not fetch user", zap.String("email", email), zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
		}
		return
	}

	err = r.emailServiceV2.SendPasswordResetEmail(ctx, *user, common.MakePasswordResetURIs(*user))
	if err != nil {
		r.logger.Error("could not send password reset email", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
	}

	ctx.HTML(http.StatusOK, "forgotPasswordEnd.gohtml", templateDataModel{
		Cfg: r.cfg,
		Data: res{
			Email: email,
		},
	})
}

func (r *frontendRouter) ResetPasswordPage(ctx *gin.Context) {
	ctx.SetCookie(authCookieName, ctx.Query("token"), int(r.cfg.Auth.UserTokenLifetime), "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)

	type res struct {
		UserId string
	}
	ctx.HTML(http.StatusOK, "resetPassword.gohtml", templateDataModel{
		Cfg: r.cfg,
		Data: res{
			UserId: ctx.Query("userId"),
		},
	})
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
		ctx.HTML(http.StatusBadRequest, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "All fields are required",
			Data: res{
				UserId: req.UserId,
			},
		})
		return
	}

	if req.Password != req.PasswordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Passwords do not match",
			Data: res{
				UserId: req.UserId,
			},
		})
		return
	}

	hashedPassword, err := auth.GetHashForPassword(req.Password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
			Data: res{
				UserId: req.UserId,
			},
		})
		return
	}

	err = r.userService.UpdateUserWithID(ctx, req.UserId, services.UserUpdateParams{
		entities.UserPassword: hashedPassword,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.String("user id", req.UserId), zap.Error(err))
			ctx.HTML(http.StatusBadRequest, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Invalid user id",
				Data: res{
					UserId: req.UserId,
				},
			})
		case services.ErrNotFound:
			r.logger.Debug("user not found", zap.Error(err))
			ctx.HTML(http.StatusNotFound, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "User not found",
				Data: res{
					UserId: req.UserId,
				},
			})
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
		}
		return
	}

	err = r.authorizer.InvalidateServiceToken(ctx, r.GetAuthToken(ctx))
	if err != nil {
		r.logger.Warn("could not invalidate service token", zap.Error(err))
	}

	ctx.SetCookie(authCookieName, "", 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	ctx.HTML(http.StatusOK, "resetPasswordEnd.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) VerifyEmail(ctx *gin.Context) {
	token := ctx.Query("token")
	if token == "" {
		r.logger.Debug("invalid token")
		ctx.HTML(http.StatusUnauthorized, "verificationTokenInvalid.gohtml", templateDataModel{
			Cfg: r.cfg,
		})
		return
	}

	user, err := r.userService.GetUserWithJWT(ctx, token)
	if err != nil {
		if err == services.ErrInvalidToken {
			r.logger.Debug("invalid token")
			ctx.HTML(http.StatusUnauthorized, "verificationTokenInvalid.gohtml", templateDataModel{
				Cfg: r.cfg,
			})
			return
		} else if err == services.ErrNotFound {
			r.logger.Debug("user not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
		}
		return
	}

	if user.AuthLevel < authlevels.Unverified {
		r.logger.Debug("user auth level too low to verify email")
		models.SendAPIError(ctx, http.StatusUnauthorized, "you are not authorized to verify your email")
		return
	}
	if user.AuthLevel > authlevels.Unverified {
		r.logger.Debug("user's email is already verified")
		models.SendAPIError(ctx, http.StatusBadRequest, "your email has already been verified")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, user.ID.Hex(), services.UserUpdateParams{
		// TODO: the default auth level after verification should be configurable via the config
		// files in case we want to implement functionality to disable applications
		entities.UserAuthLevel: authlevels.Applicant,
	})
	if err != nil {
		r.logger.Error("could not update user", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong"})
		return
	}

	ctx.HTML(http.StatusOK, "verifyEmail.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) Logout(ctx *gin.Context) {
	ctx.SetCookie(authCookieName, "", 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) CreateTeam(ctx *gin.Context) {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	name := ctx.PostForm("name")
	if len(name) == 0 {
		r.logger.Debug("team name not specified", zap.String("name", name))
		r.renderProfilePage(ctx, http.StatusBadRequest, "Please specify team name")
		return
	}

	_, err = r.teamService.CreateTeamForUserWithJWT(ctx, name, jwt)
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid auth token")
			ctx.Redirect(http.StatusSeeOther, "/login")
			return
		case services.ErrNotFound:
			r.logger.Debug("could not find user in jwt")
			ctx.Redirect(http.StatusSeeOther, "/login")
			return
		default:
			r.logger.Error("could not create new team", zap.Error(err))
			r.renderProfilePage(ctx, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}

	ctx.Redirect(http.StatusSeeOther, "/")
}

func (r *frontendRouter) JoinTeam(ctx *gin.Context) {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	team := ctx.PostForm("id")
	if len(team) == 0 {
		r.logger.Debug("team id not provided")
		r.renderProfilePage(ctx, http.StatusBadRequest, "Please specify the ID of the team to join")
		return
	}

	err = r.teamService.AddUserWithJWTToTeamWithID(ctx, jwt, team)
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid auth token")
			ctx.Redirect(http.StatusSeeOther, "/login")
			return
		case services.ErrNotFound:
			r.logger.Debug("team with id not found")
			r.renderProfilePage(ctx, http.StatusBadRequest, "Team with given ID does not exist")
			return
		case services.ErrUserInTeam:
			r.logger.Debug("user already in team")
			r.renderProfilePage(ctx, http.StatusBadRequest, "You are already in a team")
			return
		default:
			r.logger.Error("could not add user to team", zap.String("team id", team), zap.Error(err))
			r.renderProfilePage(ctx, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}

	r.renderProfilePage(ctx, http.StatusOK, "")
}

func (r *frontendRouter) LeaveTeam(ctx *gin.Context) {
	jwt, err := ctx.Cookie(authCookieName)
	if err != nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	err = r.teamService.RemoveUserWithJWTFromTheirTeam(ctx, jwt)
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid auth token")
			ctx.Redirect(http.StatusSeeOther, "/login")
			return
		case services.ErrNotFound:
			r.logger.Debug("user in token not found")
			r.renderProfilePage(ctx, http.StatusBadRequest, "Invalid auth token")
			return
		case services.ErrUserNotInTeam:
			r.logger.Debug("user is not in team")
			r.renderProfilePage(ctx, http.StatusBadRequest, "You are not in a team")
			return
		default:
			r.logger.Error("could not remove user from their team", zap.Error(err))
			r.renderProfilePage(ctx, http.StatusInternalServerError, "Something went wrong")
			return
		}
	}

	r.renderProfilePage(ctx, http.StatusOK, "")
}

func (r *frontendRouter) UpdateUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if len(userID) == 0 {
		r.logger.Debug("user id not provided")
		r.renderProfilePage(ctx, http.StatusBadRequest, "User ID not provided")
		return
	}

	var updatedFields map[entities.UserField]string
	err := json.Unmarshal([]byte(ctx.PostForm("set")), &updatedFields)

	if err != nil {
		r.logger.Debug("could not unmarshal params to update", zap.Error(err))
		r.renderProfilePage(ctx, http.StatusBadRequest, "Invalid parameters to update")
		return
	}
	// TODO: input validation should be done at the service level
	builtParams, err := services.BuildUserUpdateParams(updatedFields)
	if err != nil {
		r.logger.Debug("could not build params to update", zap.Error(err))
		r.renderProfilePage(ctx, http.StatusBadRequest, "Invalid parameters to update")
		return
	}

	if _, exists := builtParams[entities.UserPassword]; exists {
		r.logger.Debug("user's password cannot be updated")
		r.renderProfilePage(ctx, http.StatusBadRequest, "User's password cannot be changed")
		return
	}

	if _, exists := builtParams[entities.UserID]; exists {
		r.logger.Debug("user's id cannot be updated")
		r.renderProfilePage(ctx, http.StatusBadRequest, "User's id cannot be changed")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, userID, builtParams)
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id")
			r.renderProfilePage(ctx, http.StatusBadRequest, "Invalid user id provided")
			break
		default:
			r.logger.Error("could not update user with id", zap.Error(err))
			r.renderProfilePage(ctx, http.StatusInternalServerError, "Something went wrong")
			break
		}
		return
	}

	r.renderProfilePage(ctx, http.StatusOK, "")
}

func (r *frontendRouter) EmailUnverifiedPage(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "emailNotVerified.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) VerifyEmailResend(ctx *gin.Context) {
	jwt := jwtProvider(ctx)

	user, err := r.userService.GetUserWithJWT(ctx, jwt)
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid token")
			ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Invalid token"})
		case services.ErrNotFound:
			r.logger.Debug("user not found")
			ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Could not find user"})
		default:
			r.logger.Error("could not find user with jwt", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong"})
		}
		return
	}

	err = r.emailService.SendEmailVerificationEmail(*user)
	if err != nil {
		r.logger.Error("could not send email verification email", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong"})
		return
	}

	ctx.HTML(http.StatusOK, "emailVerifyResend.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}
