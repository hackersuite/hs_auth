// +build integration

package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupTest(t *testing.T) *mongo.Database {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://hs_auth:password123@localhost:8003/hs_auth"))
	assert.NoError(t, err)

	err = client.Connect(context.Background())
	assert.NoError(t, err)

	var db *mongo.Database
	// Giving some time for the DB to boot up
	for i := 0; i < 4; i++ {
		db = client.Database("hs_auth")
		err := client.Ping(context.Background(), nil)
		if err == nil {
			break
		} else if i == 3 {
			fmt.Println(err)
			panic("could not connect to db")
		}
		fmt.Println("could not connect to database, will retry in a bit")
		time.Sleep(5 * time.Second)
	}

	return db
}

func Test_NewUserRepository__should_return_users_mongo_collection(t *testing.T) {
	db := setupTest(t)

	uRepo, err := NewUserRepository(db)
	assert.NoError(t, err)

	assert.Equal(t, "users", uRepo.Name())
	db.Collection("users").Drop(context.Background())
}

func Test_NewUserRepository__create_required_number_of_indexes(t *testing.T) {
	db := setupTest(t)

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
