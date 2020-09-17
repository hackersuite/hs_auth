package v2

import (
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	v2 "github.com/unicsmcr/hs_auth/authorization/v2"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/routers/api/models"
	"github.com/unicsmcr/hs_auth/services"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
)

// POST: /api/v2/teams
// x-www-form-urlencoded
// Request:  name string
// Response: team entities.Team
// Headers:  Authorization -> token
func (r *apiV2Router) CreateTeam(ctx *gin.Context) {
	teamName := ctx.PostForm("name")
	if len(teamName) == 0 {
		r.logger.Debug("team name not provided")
		models.SendAPIError(ctx, http.StatusBadRequest, "team name must be provided")
		return
	}

	var (
		err  error
		team *entities.Team
	)
	tokenType, err := r.authorizer.GetTokenTypeFromToken(r.GetAuthToken(ctx))
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		default:
			r.logger.Error("could not extract token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	if tokenType == v2.User {
		var userId primitive.ObjectID
		userId, err = r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
		if err != nil {
			switch errors.Cause(err) {
			case common.ErrInvalidToken:
				r.logger.Debug("invalid token", zap.Error(err))
				r.HandleUnauthorized(ctx)
			case common.ErrInvalidTokenType:
				r.logger.Debug("invalid token type", zap.Error(err))
				models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
			default:
				r.logger.Error("could not extract token type", zap.Error(err))
				models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
			}
			return
		}

		team, err = r.teamService.CreateTeamForUserWithID(ctx, teamName, userId.Hex())
	} else if tokenType == v2.Service {
		team, err = r.teamService.CreateTeam(ctx, teamName, primitive.NilObjectID.Hex())
	}

	if err != nil {
		switch errors.Cause(err) {
		case services.ErrInvalidID:
			r.logger.Debug("invalid user id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid user id")
		case services.ErrNameTaken:
			r.logger.Debug("team name taken", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "given team name is already taken")
		case services.ErrUserInTeam:
			r.logger.Debug("user is already in a team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "user is already in a team")
		default:
			r.logger.Error("could not create team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, createTeamRes{
		Team: *team,
	})
}

// GET: /api/v2/teams
// Response: teams []entities.Team
// Headers:  Authorization -> token
func (r *apiV2Router) GetTeams(ctx *gin.Context) {
	teams, err := r.teamService.GetTeams(ctx)
	if err != nil {
		r.logger.Error("could not fetch teams", zap.Error(err))
		models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
	}

	ctx.JSON(http.StatusOK, getTeamsRes{
		Teams: teams,
	})
}

// GET: /api/v2/teams/(:id|me)
// Response: team entities.Team
// Headers:  Authorization -> token
func (r *apiV2Router) GetTeam(ctx *gin.Context) {
	team, err := r.getTeamCtxAware(ctx, ctx.Param("id"))
	if err != nil {
		switch errors.Cause(err) {
		case common.ErrInvalidToken:
			r.logger.Debug("invalid token", zap.Error(err))
			r.HandleUnauthorized(ctx)
		case common.ErrInvalidTokenType:
			r.logger.Debug("invalid token type", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "provided token is of invalid type for the requested operation")
		case services.ErrInvalidID:
			r.logger.Debug("invalid id", zap.Error(err))
			models.SendAPIError(ctx, http.StatusBadRequest, "invalid id")
		case services.ErrNotFound:
			r.logger.Debug("team not found", zap.Error(err))
			models.SendAPIError(ctx, http.StatusNotFound, "team not found")
		default:
			r.logger.Error("could not fetch team", zap.Error(err))
			models.SendAPIError(ctx, http.StatusInternalServerError, "something went wrong")
		}
		return
	}

	ctx.JSON(http.StatusOK, getTeamRes{
		Team: *team,
	})
}

func (r *apiV2Router) getTeamCtxAware(ctx *gin.Context, teamId string) (*entities.Team, error) {
	var (
		team *entities.Team
		err  error
	)
	if teamId == "me" {
		var userId primitive.ObjectID
		userId, err = r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
		if err != nil {
			return nil, err
		}

		team, err = r.teamService.GetTeamForUserWithID(ctx, userId.Hex())
	} else {
		team, err = r.teamService.GetTeamWithID(ctx, teamId)
	}

	if err != nil {
		return nil, errors.Wrap(err, "could not fetch team")
	}

	return team, nil
}
