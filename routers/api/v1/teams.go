package v1

import (
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/services"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"go.uber.org/zap"
)

// POST: /api/v1/teams
// x-www-form-urlencoded
// Request:  name string
// Response: status int
//           error string
//           team entities.Team
// Headers:  Authorization -> token
func (r *apiV1Router) CreateTeam(ctx *gin.Context) {
	name := ctx.PostForm("name")
	if len(name) == 0 {
		r.logger.Warn("team name not specified", zap.String("name", name))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the team's name")
		return
	}

	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("could not find user in auth claims", zap.String("id", claims.Id))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid token")
			return
		}
		r.logger.Error("could not query for user with id", zap.String("id", claims.Id), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new team")
		return
	}

	if user.Team != primitive.NilObjectID {
		r.logger.Warn("user is in a team already", zap.String("id", claims.Id), zap.String("team", user.Team.Hex()))
		models.SendAPIError(ctx, http.StatusBadRequest, "you are already in a team")
		return
	}

	_, err = r.teamService.GetTeamWithName(ctx, name)
	if err == nil {
		r.logger.Warn("team name taken", zap.String("name", name))
		models.SendAPIError(ctx, http.StatusBadRequest, "team name taken")
		return
	} else if err != services.ErrNotFound {
		r.logger.Error("could not query for team with name", zap.String("name", name), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new team")
		return
	}

	team, err := r.teamService.CreateTeam(ctx, name, claims.Id)
	if err != nil {
		r.logger.Error("could not create team", zap.String("name", name), zap.String("creator", claims.Id), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new team")
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
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong while creating new team")
		return
	}

	ctx.JSON(http.StatusOK, createTeamRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Team: *team,
	})
}
