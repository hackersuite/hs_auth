package frontend

import (
	"encoding/json"
	"github.com/unicsmcr/hs_auth/config/role"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
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
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")
	if email == "" || password == "" {
		r.logger.Debug("email or password was not provided")
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Both email and password are required",
		})
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, email, password)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Debug("user not found", zap.String("email", email))
			ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "User not found",
			})
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
		}
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), r.cfg.AuthTokenLifetime, auth.Auth, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.String("user", user.ID.Hex()), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	ctx.SetCookie(authCookieName, token, int(r.cfg.AuthTokenLifetime), "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)

	if user.AuthLevel <= authlevels.Unverified {
		r.logger.Debug("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", email))
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
	name := ctx.PostForm("name")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")
	passwordConfirm := ctx.PostForm("passwordConfirm")

	if len(name) == 0 || len(email) == 0 || len(password) == 0 {
		r.logger.Debug("one of name, email, password, passwordConfirm not specified", zap.String("name", name), zap.String("email", email), zap.Int("password length", len(password)), zap.Int("passwordConfirm length", len(passwordConfirm)))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "All fields are required",
		})
		return
	}

	// TODO: might be a good idea to handle this at the service level
	if len(password) < 6 || len(password) > 160 {
		r.logger.Debug("invalid password length", zap.Int("length", len(password)))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Password must contain between 6 and 160 characters",
		})
		return
	}

	if password != passwordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Passwords do not match",
		})
		return
	}

	user, err := r.userService.CreateUser(ctx, name, email, password, role.Unverified)
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

	err = r.emailService.SendEmailVerificationEmail(*user)
	if err != nil {
		r.logger.Error("could not send email verification email", zap.Error(err))
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
	err := r.emailService.SendPasswordResetEmailForUserWithEmail(ctx, email)
	if err != nil {
		switch err {
		case services.ErrNotFound:
			r.logger.Debug("user with email doesn't exist", zap.String("email", email))
			// don't want to give the user a tool to figure which email addresses are registered
			// as this would be a security issue
			ctx.HTML(http.StatusOK, "forgotPasswordEnd.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: res{
					Email: email,
				},
			})
			return
		default:
			r.logger.Error("could not fetch user", zap.String("email", email), zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
			return
		}
	}

	ctx.HTML(http.StatusOK, "forgotPasswordEnd.gohtml", templateDataModel{
		Cfg: r.cfg,
		Data: res{
			Email: email,
		},
	})
}

func (r *frontendRouter) ResetPasswordPage(ctx *gin.Context) {
	token := ctx.Query("token")
	email := ctx.Query("email")

	type res struct {
		Token string
		Email string
	}
	ctx.HTML(http.StatusOK, "resetPassword.gohtml", templateDataModel{
		Cfg: r.cfg,
		Data: res{
			Token: token,
			Email: email,
		},
	})
}

func (r *frontendRouter) ResetPassword(ctx *gin.Context) {
	email := ctx.PostForm("email")
	token := ctx.PostForm("token")
	password := ctx.PostForm("password")
	passwordConfirm := ctx.PostForm("passwordConfirm")

	type res struct {
		Token string
		Email string
	}

	if len(email) == 0 || len(password) == 0 || len(passwordConfirm) == 0 {
		r.logger.Debug("one of email, password, passwordConfirm not specified", zap.String("email", email), zap.Int("password len", len(password)), zap.Int("passwordConfirm len", len(passwordConfirm)))
		ctx.HTML(http.StatusBadRequest, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "All fields are required",
			Data: res{
				Token: token,
				Email: email,
			},
		})
		return
	}

	if password != passwordConfirm {
		r.logger.Debug("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Passwords do not match",
			Data: res{
				Token: token,
				Email: email,
			},
		})
		return
	}

	hashedPassword, err := auth.GetHashForPassword(password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
			Data: res{
				Token: token,
				Email: email,
			},
		})
		return
	}

	err = r.userService.UpdateUserWithJWT(ctx, token, services.UserUpdateParams{
		entities.UserPassword: hashedPassword,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid token")
			ctx.HTML(http.StatusUnauthorized, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Invalid token",
				Data: res{
					Token: token,
					Email: email,
				},
			})
			return
		case services.ErrNotFound:
			r.logger.Debug("could not find user with token")
			ctx.HTML(http.StatusUnauthorized, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Could not find user with given auth token",
				Data: res{
					Token: token,
					Email: email,
				},
			})
			return
		default:
			r.logger.Error("could not update user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
				Data: res{
					Token: token,
					Email: email,
				},
			})
			return
		}
	}

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
