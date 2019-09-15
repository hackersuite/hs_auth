// +build integration

package repositories

import (
	"context"
	"testing"

	"github.com/unicsmcr/hs_auth/testutils"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

func Test_NewUserRepository__should_return_users_mongo_collection(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	uRepo, err := NewUserRepository(db)
	assert.NoError(t, err)

	assert.Equal(t, "users", uRepo.Name())
	db.Collection("users").Drop(context.Background())
}

func Test_NewUserRepository__create_required_number_of_indexes(t *testing.T) {
	db := testutils.ConnectToIntegrationTestDB(t)

	_, err := NewUserRepository(db)
	assert.NoError(t, err)

	cur, err := db.Collection("users").Indexes().List(context.Background())
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
	db.Collection("users").Drop(context.Background())
}
