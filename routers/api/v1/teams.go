package v1

import (
	"net/http"

	"github.com/unicsmcr/hs_auth/utils/auth/common"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/services"

	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/routers/api/models"
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

// GET: /api/v1/teams/:id
// Response: status int
//           error string
//           team entities.Team
// Headers:  Authorization -> token
func (r *apiV1Router) GetMyTeam(ctx *gin.Context) {
	team := ctx.Param("id")
	if len(team) == 0 {
		r.logger.Warn("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	_, err := primitive.ObjectIDFromHex(team)
	if err != nil {
		r.logger.Warn("invalid team id", zap.String("id", team))
		models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id")
		return
	}

	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
		return
	}

	userTeam, err := r.teamService.GetTeamWithID(ctx, team)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("team with given id does not exist", zap.String("id", team))
			models.SendAPIError(ctx, http.StatusBadRequest, "could not find team with given id")
			return
		}
		r.logger.Error("could not fetch team with id", zap.String("id", team), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	ctx.JSON(http.StatusOK, getTeamRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Team: *userTeam,
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

// DELETE: /api/v1/teams/leave
// Response: status int
//           error string
// Headers:  Authorization -> token
func (r *apiV1Router) LeaveTeam(ctx *gin.Context) {
	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
		return
	}

	user, err := r.userService.GetUserWithID(ctx, claims.Id)
	if err != nil {
		r.logger.Error("could not fetch user", zap.String("user id", claims.Id), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	if user.Team == primitive.NilObjectID {
		r.logger.Warn("user is not in a team", zap.String("user id", claims.Id))
		models.SendAPIError(ctx, http.StatusBadRequest, "you are not in a team")
		return
	}

	team, err := r.teamService.GetTeamWithID(ctx, user.Team.Hex())
	if err != nil {
		r.logger.Error("could not fetch user's team", zap.String("user id", claims.Id), zap.String("team id", user.Team.Hex()), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	if team.Creator == user.ID {
		// Team creator left team, deleting team and removing all members from the team
		err := r.userService.UpdateUsersWithTeam(ctx, team.ID.Hex(), map[string]interface{}{
			"team": primitive.NilObjectID,
		})
		if err != nil {
			r.logger.Error("could not remove users from team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			return
		}
		err = r.teamService.DeleteTeamWithID(ctx, team.ID.Hex())
		if err != nil {
			r.logger.Error("could not delete team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			return
		}
	} else {
		err := r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
			"team": primitive.NilObjectID,
		})
		if err != nil {
			r.logger.Error("user could not leave their team", zap.String("user id", claims.Id), zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			return
		}
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
		r.logger.Warn("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	teamID, err := primitive.ObjectIDFromHex(team)
	if err != nil {
		r.logger.Warn("invalid team id", zap.String("id", team))
		models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id")
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
		r.logger.Error("could not fetch user with id", zap.String("id", claims.Id), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	if user.Team != primitive.NilObjectID {
		r.logger.Warn("user already has a team", zap.String("user id", claims.Id), zap.String("team id", user.Team.Hex()))
		models.SendAPIError(ctx, http.StatusBadRequest, "you are already in a team")
		return
	}

	_, err = r.teamService.GetTeamWithID(ctx, team)
	if err != nil {
		if err == services.ErrNotFound {
			r.logger.Warn("team with given id does not exist", zap.String("id", team))
			models.SendAPIError(ctx, http.StatusBadRequest, "could not find team with given id")
			return
		}
		r.logger.Error("could not fetch team with id", zap.String("id", team), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		return
	}

	err = r.userService.UpdateUserWithID(ctx, claims.Id, map[string]interface{}{
		"team": teamID,
	})
	if err != nil {
		r.logger.Error("could not set users team", zap.String("user id", claims.Id), zap.String("team id", team), zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
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
		r.logger.Warn("team id not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team id must be provided")
		return
	}

	claims := extractClaimsFromCtx(ctx)
	if claims == nil {
		r.logger.Warn("could not extract auth claims from request context")
		models.SendAPIError(ctx, http.StatusBadRequest, "missing auth information")
		return
	}

	if claims.AuthLevel < common.Organizer {
		user, err := r.userService.GetUserWithID(ctx, claims.Id)
		if err != nil {
			r.logger.Error("could not fetch user with id", zap.String("id", claims.Id), zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			return
		}

		if user.Team.Hex() != team {
			r.logger.Warn("user is not in team and has an auth level less than organizer",
				zap.String("user id", claims.Id),
				zap.String("user's team", user.Team.Hex()),
				zap.Int("user's auth level", int(claims.AuthLevel)),
				zap.String("team id in request", team))
			// don't want to reveal to the user that a team with given id exists
			// as the id can be used to join the team
			models.SendAPIError(ctx, http.StatusBadRequest, "could not find team with given id")
			return
		}
	}

	users, err := r.userService.GetUsersWithTeam(ctx, team)
	if err != nil {
		if err == services.ErrInvalidID {
			r.logger.Warn("invalid team id", zap.String("id", team))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid team id")
			return
		} else if err == services.ErrNotFound {
			r.logger.Warn("team with given id doesn't exist", zap.String("id", team))
			models.SendAPIError(ctx, http.StatusBadRequest, "could not find team with given id")
			return
		} else {
			r.logger.Error("could not fetch team with id", zap.String("id", team), zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			return
		}
	}

	ctx.JSON(http.StatusOK, getTeamMembersRes{
		Response: models.Response{
			Status: http.StatusOK,
		},
		Users: users,
	})
}
