// +build integration

package repositories

import (
	"context"
	"testing"

	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/stretchr/testify/assert"
)

func Test_NewTeamRepository__should_return_teams_mongo_collection(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	tRepo, err := NewTeamRepository(db)
	assert.NoError(t, err)

	assert.Equal(t, "teams", tRepo.Name())
	db.Collection("teams").Drop(context.Background())
}

func Test_NewTeamRepository__create_required_number_of_indexes(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	_, err := NewTeamRepository(db)
	assert.NoError(t, err)

	cur, err := db.Collection("teams").Indexes().List(context.Background())
	assert.NoError(t, err)
	defer cur.Close(context.Background())

	var noOfIndexes int
	for cur.Next(context.Background()) {
		var index mongo.IndexModel
		err = cur.Decode(&index)
		assert.NoError(t, err)
		noOfIndexes++
	}

	assert.Equal(t, 2, noOfIndexes)
	db.Collection("teams").Drop(context.Background())
}
