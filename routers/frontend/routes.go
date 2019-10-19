package frontend

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

const ReturnToCookie = "ReturnTo"

func getClaimsFromAuthCookie(ctx *gin.Context, jwtSecret string) *auth.Claims {
	authCookie, err := ctx.Cookie(auth.AuthHeaderName)
	if err != nil {
		return nil
	}

	claims := auth.GetJWTClaims(authCookie, []byte(jwtSecret))
	if claims == nil || claims.TokenType != auth.Auth {
		return nil
	}

	return claims
}

type basicUserInfo struct {
	User      *entities.User
	Team      *entities.Team
	Teammates []entities.User
}

func (r *frontendRouter) getBasicUserInfo(ctx *gin.Context, claims *auth.Claims) (basicUserInfo, error) {
	user, _ := r.userService.GetUserWithID(ctx, claims.Id)
	// TODO: error handling

	var team *entities.Team
	var teammates []entities.User
	if user.Team != primitive.NilObjectID {
		team, _ = r.teamService.GetTeamWithID(ctx, user.Team.Hex())
		teammates, _ = r.userService.GetUsersWithTeam(ctx, user.Team.Hex())
	}

	for index, teammate := range teammates {
		if teammate.ID == user.ID { // removing the user themself from the teammates
			teammates = append(teammates[:index], teammates[index+1:]...)
			break
		}
	}

	return basicUserInfo{
		User:      user,
		Team:      team,
		Teammates: teammates,
	}, nil
}

func (r *frontendRouter) ProfilePage(ctx *gin.Context) {
	claims := getClaimsFromAuthCookie(ctx, r.env.Get(environment.JWTSecret))
	if claims == nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusPermanentRedirect, "/login")
		return
	}

	userInfo, err := r.getBasicUserInfo(ctx, claims)
	if err != nil {
		r.logger.Error("could not get user's basic info", zap.Error(err))
		ctx.Redirect(http.StatusPermanentRedirect, "/login")
		return
	}

	ctx.HTML(http.StatusOK, "profile.gohtml", templateDataModel{
		Cfg:  r.cfg,
		Data: userInfo,
	})
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
	if email == "" {
		r.logger.Warn("email was not provided")
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Email is required",
		})
		return
	}

	password := ctx.PostForm("password")
	if password == "" {
		r.logger.Warn("password was not provided")
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Password is required",
		})
		return
	}

	user, err := r.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
			ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
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

	err = auth.CompareHashAndPassword(user.Password, password)
	if err != nil {
		r.logger.Warn("user not found", zap.String("email", email))
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "User not found",
		})
		return
	}

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

	ctx.SetCookie(auth.AuthHeaderName, token, 100000, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
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

	if len(password) < 6 || len(password) > 160 {
		r.logger.Warn("invalid password lenght", zap.Int("length", len(password)))
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

	_, err := r.userService.GetUserWithEmail(ctx, email)
	if err == nil {
		r.logger.Warn("email taken", zap.String("email", email))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Email taken",
		})
		return
	}

	if err != services.ErrNotFound {
		r.logger.Error("could not query for user with email", zap.String("email", email), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	hashedPassword, err := auth.GetHashForPassword(password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	user, err := r.userService.CreateUser(ctx, name, email, hashedPassword, r.cfg.BaseAuthLevel)
	if err != nil {
		r.logger.Error("could not create user",
			zap.String("name", name),
			zap.String("email", email),
			zap.Int("auth level", int(r.cfg.BaseAuthLevel)),
			zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	emailToken, err := auth.NewJWT(*user, time.Now().Unix(), r.cfg.AuthTokenLifetime, auth.Email, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not generate JWT token",
			zap.String("user id", user.ID.Hex()),
			zap.Bool("JWT_SECRET set", r.env.Get(environment.JWTSecret) != environment.DefaultEnvVarValue),
			zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
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
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		r.userService.DeleteUserWithEmail(ctx, email)
		return
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
	user, err := r.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		if err == services.ErrNotFound {
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
		}
		r.logger.Error("could not fetch user", zap.String("email", email), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	emailToken, err := auth.NewJWT(*user, time.Now().Unix(), r.cfg.AuthTokenLifetime, auth.Email, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not make email token for user",
			zap.String("user id", user.ID.Hex()),
			zap.String("jwt secret env var name", environment.JWTSecret),
			zap.Bool("jwt secret set", r.env.Get(environment.JWTSecret) == environment.DefaultEnvVarValue),
			zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	err = r.emailService.SendPasswordResetEmail(*user, emailToken)
	if err != nil {
		r.logger.Error("could not send password reset email", zap.String("user id", user.ID.Hex()), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "forgotPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
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
		r.logger.Warn("password passwordConfirm do not match")
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

	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))
	if claims == nil {
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
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		r.logger.Error("could not fetch user", zap.String("user id", claims.Id), zap.Error(err))
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

	if user.Email != email {
		r.logger.Warn("user's in token email is different than email in request", zap.String("user's email", user.Email), zap.String("given email", email))
		ctx.HTML(http.StatusUnauthorized, "resetPassword.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Invalid token",
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

	user.Password = hashedPassword
	err = r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
		"password": user.Password,
	})
	if err != nil {
		r.logger.Error("could not user's password", zap.String("user id", user.ID.Hex()), zap.Error(err))
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

	ctx.HTML(http.StatusOK, "resetPasswordEnd.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) VerifyEmail(ctx *gin.Context) {
	token := ctx.Query("token")
	r.logger.Info("token", zap.Any("token", token))
	claims := auth.GetJWTClaims(token, []byte(r.env.Get(environment.JWTSecret)))

	if claims == nil || claims.TokenType != auth.Email {
		r.logger.Warn("invalid token")
		ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Invalid token",
		})
		return
	}

	fieldsToUpdate := map[string]interface{}{
		"email_verified": true,
	}
	err := r.userService.UpdateUserWithID(ctx, claims.Id, fieldsToUpdate)
	if err != nil {
		r.logger.Error("could not update user", zap.String("user id", claims.Id), zap.Any("fields to udpate", fieldsToUpdate))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Err: "Something went wrong",
		})
		return
	}

	ctx.HTML(http.StatusOK, "verifyEmail.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) Logout(ctx *gin.Context) {
	ctx.SetCookie(auth.AuthHeaderName, "", 0, "", r.cfg.DomainName, r.cfg.UseSecureCookies, true)
	ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
		Cfg: r.cfg,
	})
}

func (r *frontendRouter) CreateTeam(ctx *gin.Context) {
	claims := getClaimsFromAuthCookie(ctx, r.env.Get(environment.JWTSecret))
	if claims == nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	name := ctx.PostForm("name")
	if len(name) == 0 {
		r.logger.Warn("team name not specified", zap.String("name", name))
		ctx.Set("err", "Please speicify team name")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("could not find user in auth claims", zap.String("id", claims.Id))
			ctx.Redirect(http.StatusSeeOther, "/login")
			return
		}
		r.logger.Error("could not query for user with id", zap.String("id", claims.Id), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	if user.Team != primitive.NilObjectID {
		r.logger.Warn("user is in a team already", zap.String("id", claims.Id), zap.String("team", user.Team.Hex()))
		ctx.Header("err", "You are already in a team")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	_, err = r.teamService.GetTeamWithName(ctx, name)
	if err == nil {
		r.logger.Warn("team name taken", zap.String("name", name))
		ctx.Set("err", "Team name is already taken")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	} else if err != services.ErrNotFound {
		r.logger.Error("could not query for team with name", zap.String("name", name), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	team, err := r.teamService.CreateTeam(ctx, name, claims.Id)
	if err != nil {
		r.logger.Error("could not create team", zap.String("name", name), zap.String("creator", claims.Id), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
		"team": team.ID,
	})
	if err != nil {
		r.logger.Error("could not add user to newly created team",
			zap.String("user id", claims.Id),
			zap.String("team id", team.ID.Hex()),
			zap.Error(err))
		if err := r.teamService.DeleteTeamWithID(ctx, team.ID.Hex()); err != nil {
			r.logger.Error("could not delete team after failing to update user's team",
				zap.String("user id", claims.Id),
				zap.String("team id", team.ID.Hex()),
				zap.Error(err))
		}
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	ctx.Redirect(http.StatusSeeOther, "/")
}

func (r *frontendRouter) JoinTeam(ctx *gin.Context) {
	claims := getClaimsFromAuthCookie(ctx, r.env.Get(environment.JWTSecret))
	if claims == nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	team := ctx.PostForm("id")
	if len(team) == 0 {
		r.logger.Warn("team id not provided")
		ctx.Set("err", "Please specify the ID of the team to join")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	teamID, err := primitive.ObjectIDFromHex(team)
	if err != nil {
		r.logger.Warn("invalid team id", zap.String("id", team))
		models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id")
		ctx.Set("err", "Invalid team ID")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		r.logger.Error("could not fetch user with id", zap.String("id", claims.Id), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	if user.Team != primitive.NilObjectID {
		r.logger.Warn("user already has a team", zap.String("user id", claims.Id), zap.String("team id", user.Team.Hex()))
		ctx.Set("err", "You are already in a team")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	_, err = r.teamService.GetTeamWithID(ctx, team)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("team with given id does not exist", zap.String("id", team))
			ctx.Set("err", "Could not find team with given ID")
			ctx.Redirect(http.StatusSeeOther, "/")
			return
		}
		r.logger.Error("could not fetch team with id", zap.String("id", team), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
		"team": teamID,
	})
	if err != nil {
		r.logger.Error("could not set users team", zap.String("user id", claims.Id), zap.String("team id", team), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	ctx.Redirect(http.StatusSeeOther, "/")
}
func (r *frontendRouter) LeaveTeam(ctx *gin.Context) {
	claims := getClaimsFromAuthCookie(ctx, r.env.Get(environment.JWTSecret))
	if claims == nil {
		r.logger.Debug("invalid auth token")
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		r.logger.Error("could not fetch user", zap.String("user id", claims.Id), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	if user.Team == primitive.NilObjectID {
		r.logger.Warn("user is not in a team", zap.String("user id", claims.Id))
		ctx.Set("err", "You are not in a team")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	team, err := r.teamService.GetTeamWithID(ctx, user.Team.Hex())
	if err != nil {
		r.logger.Error("could not fetch user's team", zap.String("user id", claims.Id), zap.String("team id", user.Team.Hex()), zap.Error(err))
		ctx.Set("err", "Something went wrong")
		ctx.Redirect(http.StatusSeeOther, "/")
		return
	}

	if team.Creator == user.ID {
		// Team creator left team, deleting team and removing all members from the team
		err := r.userService.UpdateUsersWithTeam(ctx, team.ID.Hex(), map[string]interface{}{
			"team": primitive.NilObjectID,
		})
		if err != nil {
			r.logger.Error("could not remove users from team", zap.Error(err))
			ctx.Set("err", "Something went wrong")
			ctx.Redirect(http.StatusSeeOther, "/")
			return
		}
		err = r.teamService.DeleteTeamWithID(ctx, team.ID.Hex())
		if err != nil {
			r.logger.Error("could not delete team", zap.Error(err))
			ctx.Set("err", "Something went wrong")
			ctx.Redirect(http.StatusSeeOther, "/")
			return
		}
	} else {
		err := r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
			"team": primitive.NilObjectID,
		})
		if err != nil {
			r.logger.Error("user could not leave their team", zap.String("user id", claims.Id), zap.Error(err))
			ctx.Set("err", "Something went wrong")
			ctx.Redirect(http.StatusSeeOther, "/")
			return
		}
	}

	ctx.Redirect(http.StatusSeeOther, "/")
}
