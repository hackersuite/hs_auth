package services

import (
	"context"

	"github.com/unicsmcr/hs_auth/entities"
)

type TeamService interface {
	CreateTeam(ctx context.Context, name, creatorID string) (*entities.Team, error)
	CreateTeamForUserWithID(ctx context.Context, name, userID string) (*entities.Team, error)
	CreateTeamForUserWithJWT(ctx context.Context, name, jwt string) (*entities.Team, error)

	GetTeams(context.Context) ([]entities.Team, error)

	GetTeamWithID(ctx context.Context, id string) (*entities.Team, error)
	GetTeamWithName(ctx context.Context, name string) (*entities.Team, error)
	GetTeamForUserWithID(ctx context.Context, userID string) (*entities.Team, error)
	GetTeamForUserWithEmail(ctx context.Context, email string) (*entities.Team, error)
	GetTeamForUserWithJWT(ctx context.Context, jwt string) (*entities.Team, error)

	DeleteTeamWithID(ctx context.Context, id string) error

	AddUserWithIDToTeamWithID(ctx context.Context, userID string, teamID string) error
	AddUserWithJWTToTeamWithID(ctx context.Context, jwt string, teamID string) error

	RemoveUserWithIDFromTheirTeam(ctx context.Context, userID string) error
	RemoveUserWithJWTFromTheirTeam(ctx context.Context, jwt string) error
}
