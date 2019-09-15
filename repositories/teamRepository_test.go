// +build integration

package repositories

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewTeamRepository__should_return_teams_mongo_collection(t *testing.T) {
	db := setupTest(t)

	tRepo := NewTeamRepository(db)

	assert.Equal(t, "teams", tRepo.Name())
	db.Collection("teams").Drop(context.Background())
}
