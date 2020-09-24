// +build integration

package repositories

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/mongo"
)

func Test_NewTokenRepository__should_return_tokens_mongo_collection(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	uRepo, err := NewTokenRepository(db)
	assert.NoError(t, err)

	assert.Equal(t, "tokens", uRepo.Name())
	db.Collection("tokens").Drop(context.Background())
}

func Test_NewTokenRepository__create_required_number_of_indexes(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	_, err := NewTokenRepository(db)
	assert.NoError(t, err)

	cur, err := db.Collection("tokens").Indexes().List(context.Background())
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
	db.Collection("tokens").Drop(context.Background())
}
