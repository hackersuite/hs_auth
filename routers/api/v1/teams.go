package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.uber.org/zap"
)

// GET: /api/v1/teams
// Response: status int
//           error string
//           teams []entities.Team
// Headers:  Authorization -> token
func (r *apiV1Router) GetTeams(ctx *gin.Context) {
	teams, err := r.teamService.GetTeams(ctx)
	if err != nil {
		r.logger.Error("could not fetch teams", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "could not fetch teams")
		return
	}

	ctx.JSON(http.StatusOK, getTeamsRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Teams: teams,
	})
}

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
		r.logger.Debug("team name not specified", zap.String("name", name))
		models.SendAPIError(ctx, http.StatusBadRequest, "request must include the team's name")
		return
	}

	team, err := r.teamService.CreateTeamForUserWithJWT(ctx, name, ctx.GetHeader(authHeaderName))
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
			break
		case services.ErrNotFound:
			r.logger.Debug("user not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "user not found")
			break
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in a team")
			models.SendAPIError(ctx, http.StatusBadRequest, "user is already in a team")
			break
		default:
			r.logger.Error("could not create new team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with fetching the user")
			break
		}
		return
	}

	ctx.JSON(http.StatusOK, createTeamRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Team: *team,
	})
}

// DELETE: /api/v1/teams/leave
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) LeaveTeam(ctx *gin.Context) {
	err := r.teamService.RemoveUserWithJWTFromTheirTeam(ctx, ctx.GetHeader(authHeaderName))
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
			break
		case services.ErrNotFound:
			r.logger.Debug("user or user's team not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "user or user's team not found")
			break
		case services.ErrUserNotInTeam:
			r.logger.Debug("user is not in a team")
			models.SendAPIError(ctx, http.StatusBadRequest, "user is not in a team")
			break
		default:
			r.logger.Error("could not remove user from team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with removing user from team")
			break
		}
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// POST: /api/v1/teams/:id/join
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) JoinTeam(ctx *gin.Context) {
	team := ctx.Param("id")
	if len(team) == 0 {
		r.logger.Debug("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	err := r.teamService.AddUserWithJWTToTeamWithID(ctx, ctx.GetHeader(authHeaderName), team)
	if err != nil {
		switch err {
		case services.ErrInvalidToken:
			r.logger.Debug("invalid token")
			models.SendAPIError(ctx, http.StatusUnauthorized, "invalid auth token")
			break
		case services.ErrInvalidID:
			r.logger.Debug("invalid team id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid auth id")
			break
		case services.ErrNotFound:
			r.logger.Debug("team not found")
			models.SendAPIError(ctx, http.StatusBadRequest, "team not found")
			break
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in a team")
			models.SendAPIError(ctx, http.StatusBadRequest, "user is already in a team")
			break
		default:
			r.logger.Error("could not add user to team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with adding user to team")
			break
		}
		return
	}

	ctx.JSON(http.StatusOK, models.Response{
		Status: http.StatusOK,
	})
}

// GET: /api/v1/teams/:id/members
// Response: status int
//           error string
//           users []entities.User
// Headers:  Authorization -> token
func (r *apiV1Router) GetTeamMembers(ctx *gin.Context) {
	team := ctx.Param("id")
	if len(team) == 0 {
		r.logger.Debug("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	teamMembers, err := r.userService.GetUsersWithTeam(ctx, team)
	if err != nil {
		switch err {
		case services.ErrInvalidID:
			r.logger.Debug("invalid team id")
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id provided")
			break
		default:
			r.logger.Error("could fetch users with team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "there was a problem with finding users in the team")
			break
		}
		return
	}

	ctx.JSON(http.StatusOK, getTeamMembersRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: teamMembers,
	})
}
