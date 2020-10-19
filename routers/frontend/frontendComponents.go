package frontend

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/services"
)

const defaultComponentsGroup = "Default"

var (
	navbar = frontendComponent{
		name:         fmt.Sprintf("%s:Navbar", defaultComponentsGroup),
		dataProvider: navbarDataProvider,
	}

	personalInformationPanel = frontendComponent{
		name:         fmt.Sprintf("%s:PersonalInformationPanel", defaultComponentsGroup),
		dataProvider: personalInformationPanelDataProvider,
	}

	teamPanel = frontendComponent{
		name:         "TeamPanel",
		dataProvider: teamPanelDataProvider,
	}

	usersListPanel = frontendComponent{
		name:         "UsersListPanel",
		dataProvider: usersListPanelDataProvider,
	}
)

func navbarDataProvider(ctx *gin.Context, _ *frontendRouter) (interface{}, error) {
	returnTo, err := ctx.Cookie(returnToCookie)
	if err != nil {
		returnTo = ""
	}

	return navbarDataModel{
		ReturnTo: returnTo,
	}, nil
}

func personalInformationPanelDataProvider(ctx *gin.Context, r *frontendRouter) (interface{}, error) {
	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "could not get user id from token")
	}

	user, err := r.userService.GetUserWithID(ctx, userId.Hex())
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not fetch user %s", userId.Hex()))
	}

	return personalInformationPanelDataModel{
		Name:  user.Name,
		Email: user.Email,
	}, nil
}

func teamPanelDataProvider(ctx *gin.Context, r *frontendRouter) (interface{}, error) {
	userId, err := r.authorizer.GetUserIdFromToken(r.GetAuthToken(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "could not get user id from token")
	}

	team, err := r.teamService.GetTeamForUserWithID(ctx, userId.Hex())
	if err != nil && err != services.ErrNotFound {
		return nil, errors.Wrap(err, fmt.Sprintf("could not fetch team for user %s", userId.Hex()))
	}

	teammates, err := r.userService.GetTeammatesForUserWithID(ctx, userId.Hex())
	if err != nil && err != services.ErrUserNotInTeam {
		return nil, errors.Wrap(err, fmt.Sprintf("could not fetch teammates for user %s", userId.Hex()))
	}

	return teamPanelDataModel{
		Team:                 team,
		Teammates:            teammates,
		TeamMembersSoftLimit: r.cfg.TeamMembersSoftLimit,
	}, nil
}

func usersListPanelDataProvider(ctx *gin.Context, r *frontendRouter) (interface{}, error) {
	users, err := r.userService.GetUsers(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch users")
	}

	return usersListPanelDataModel{
		Users: users,
	}, nil
}

type frontendComponent struct {
	name         string
	dataProvider frontendComponentDataProvider
}

type frontendComponents []frontendComponent

type frontendComponentDataProvider func(*gin.Context, *frontendRouter) (interface{}, error)
