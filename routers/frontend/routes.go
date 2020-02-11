package frontend

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const ReturnToCookie = "ReturnTo"

type basicUserInfo struct {
	User      *entities.User
	Team      *entities.Team
	Teammates []entities.User
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

	userInfo, routerErr := r.getBasicUserInfo(ctx, jwt)
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

func (r *frontendRouter) getBasicUserInfo(ctx *gin.Context, jwt string) (basicUserInfo, error) {
	user, err := r.userService.GetUserWithJWT(ctx, jwt)
	if err != nil {
		return basicUserInfo{}, err
	}
	var team *entities.Team
	var teammates []entities.User
	if user.Team != primitive.NilObjectID {
		team, err = r.teamService.GetTeamWithID(ctx, user.Team.Hex())
		if err != nil {
			return basicUserInfo{
				User: user,
			}, nil
		}
		teammates, err = r.userService.GetTeammatesForUserWithID(ctx, user.ID.Hex())
		if err != nil {
			return basicUserInfo{
				User:      user,
				Team:      team,
				Teammates: []entities.User{},
			}, nil
		}
	}

	return basicUserInfo{
		User:      user,
		Team:      team,
		Teammates: teammates,
	}, nil
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
		r.logger.Warn("email or password was not provided")
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Both email and password are required",
		})
		return
	}

	user, err := r.userService.GetUserWithEmailAndPwd(ctx, email, password)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
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

	// TODO: should allow the user to resend verification email
	if !user.EmailVerified {
		r.logger.Warn("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", email))
		ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "User's email not verified",
		})
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

	ctx.SetCookie(authCookieName, token, 100000, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
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
		r.logger.Warn("one of name, email, password, passwordConfirm not specified", zap.String("name", name), zap.String("email", email), zap.Int("password length", len(password)), zap.Int("passwordConfirm length", len(passwordConfirm)))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "All fields are required",
		})
		return
	}

	// TODO: might be a good idea to handle this at the service level
	if len(password) < 6 || len(password) > 160 {
		r.logger.Warn("invalid password length", zap.Int("length", len(password)))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Password must contain between 6 and 160 characters",
		})
		return
	}

	if password != passwordConfirm {
		r.logger.Warn("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Passwords do not match",
		})
		return
	}

	user, err := r.userService.CreateUser(ctx, name, email, password)
	if err != nil {
		switch err {
		case services.ErrEmailTaken:
			r.logger.Warn("email taken")
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
		r.logger.Warn("email not specified")
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
			r.logger.Warn("user with email doesn't exist", zap.String("email", email))
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
		r.logger.Warn("one of email, password, passwordConfirm not specified", zap.String("email", email), zap.Int("password len", len(password)), zap.Int("passwordConfirm len", len(passwordConfirm)))
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
		r.logger.Warn("password and passwordConfirm do not match")
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
			r.logger.Warn("invalid token")
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
			r.logger.Warn("could not find user with token")
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
		r.logger.Warn("empty token")
		ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Invalid token",
		})
		return
	}

	err := r.userService.UpdateUserWithJWT(ctx, token, services.UserUpdateParams{
		entities.UserEmailVerified: true,
	})
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Warn("invalid token")
			ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Invalid token",
			})
			return
		case services.ErrNotFound:
			r.logger.Warn("could not find user with token")
			ctx.HTML(http.StatusUnauthorized, "resetPassword.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Couldn't find user with given auth token",
			})
			return
		default:
			r.logger.Error("could not update user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Err: "Something went wrong",
			})
			return
		}
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
		r.logger.Warn("team name not specified", zap.String("name", name))
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
		r.logger.Warn("team id not provided")
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
			r.logger.Warn("team with id not found")
			r.renderProfilePage(ctx, http.StatusBadRequest, "Team with given ID does not exist")
			return
		case services.ErrUserInTeam:
			r.logger.Warn("user already in team")
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
			r.logger.Warn("user in token not found")
			r.renderProfilePage(ctx, http.StatusBadRequest, "Invalid auth token")
			return
		case services.ErrUserNotInTeam:
			r.logger.Warn("user is not in team")
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
