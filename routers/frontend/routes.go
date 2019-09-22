package frontend

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/utils/auth"
	"go.uber.org/zap"
)

func (r *frontendRouter) LoginPage(ctx *gin.Context) {
	referer := ctx.GetHeader("Referer")
	if len(referer) > 0 {
		ctx.SetCookie("Referer", referer, 100, "", "", false, true)
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
			Data: models.Response{
				Err: "Email is required",
			},
		})
		return
	}

	password := ctx.PostForm("password")
	if password == "" {
		r.logger.Warn("password was not provided")
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Password is required",
			},
		})
		return
	}

	user, err := r.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
			ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: models.Response{
					Err: "User not found",
				},
			})
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: models.Response{
					Err: "Something went wrong",
				},
			})
		}
		return
	}

	err = auth.CompareHashAndPassword(user.Password, password)
	if err != nil {
		r.logger.Warn("user not found", zap.String("email", email))
		ctx.HTML(http.StatusBadRequest, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "User not found",
			},
		})
		return
	}

	if !user.EmailVerified {
		r.logger.Warn("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", email))
		ctx.HTML(http.StatusUnauthorized, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "User's email not verified",
			},
		})
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), 0, auth.Auth, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.String("user", user.ID.Hex()), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Something went wrong",
			},
		})
		return
	}

	ctx.Header(auth.AuthHeaderName, token)
	ctx.SetCookie(auth.AuthHeaderName, token, 100000, "", "", false, true)
	referer, err := ctx.Cookie("Referer")
	if err != nil {
		referer = "/"
	}
	ctx.SetCookie("Referer", "", 0, "", "", false, true)
	ctx.Redirect(http.StatusMovedPermanently, referer)
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
			Data: models.Response{
				Err: "All fields are required",
			},
		})
		return
	}

	if password != passwordConfirm {
		r.logger.Warn("password and passwordConfirm do not match")
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Passwords do not match",
			},
		})
		return
	}

	_, err := r.userService.GetUserWithEmail(ctx, email)
	if err == nil {
		r.logger.Warn("email taken", zap.String("email", email))
		ctx.HTML(http.StatusBadRequest, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Email taken",
			},
		})
		return
	}

	if err != services.ErrNotFound {
		r.logger.Error("could not query for user with email", zap.String("email", email), zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Something went wrong",
			},
		})
		return
	}

	hashedPassword, err := auth.GetHashForPassword(password)
	if err != nil {
		r.logger.Error("could not make hash for password", zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Something went wrong",
			},
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
			Data: models.Response{
				Err: "Something went wrong",
			},
		})
		return
	}

	// TODO: change validityDuration placeholder once token validity duration is implemented
	emailToken, err := auth.NewJWT(*user, time.Now().Unix(), 0, auth.Email, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not generate JWT token",
			zap.String("user id", user.ID.Hex()),
			zap.Bool("JWT_SECRET set", r.env.Get(environment.JWTSecret) != environment.DefaultEnvVarValue),
			zap.Error(err))
		ctx.HTML(http.StatusInternalServerError, "register.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "Something went wrong",
			},
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
			Data: models.Response{
				Err: "Something went wrong",
			},
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
