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
		ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "email is required",
			},
		})
		return
	}

	password := ctx.PostForm("password")
	if password == "" {
		r.logger.Warn("password was not provided")
		ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "password is required",
			},
		})
		return
	}

	user, err := r.userService.GetUserWithEmail(ctx, email)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("user not found", zap.String("email", email))
			ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: models.Response{
					Err: "user not found",
				},
			})
		} else {
			r.logger.Error("could not fetch user", zap.Error(err))
			ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
				Cfg: r.cfg,
				Data: models.Response{
					Err: "something went wrong",
				},
			})
		}
		return
	}

	err = auth.CompareHashAndPassword(user.Password, password)
	if err != nil {
		r.logger.Warn("user not found", zap.String("email", email))
		ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "user not found",
			},
		})
		return
	}

	if !user.EmailVerified {
		r.logger.Warn("user's email not verified", zap.String("user id", user.ID.Hex()), zap.String("email", email))
		ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "user's email not verified",
			},
		})
		return
	}

	token, err := auth.NewJWT(*user, time.Now().Unix(), 0, auth.Auth, []byte(r.env.Get(environment.JWTSecret)))
	if err != nil {
		r.logger.Error("could not create JWT", zap.String("user", user.ID.Hex()), zap.Error(err))
		ctx.HTML(http.StatusOK, "login.gohtml", templateDataModel{
			Cfg: r.cfg,
			Data: models.Response{
				Err: "something went wrong",
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
