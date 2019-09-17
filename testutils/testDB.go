package testutils

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const dbUser = "hs_auth"
const dbPassword = "password123"
const dbAddress = "localhost:8003"
const dbDatabase = "hs_auth"

// ConnectToIntegrationTestDB waits for the integrations tests DB to become available
// and returns a connection to the DB
func ConnectToIntegrationTestDB(t *testing.T) *mongo.Database {
	client, err := mongo.NewClient(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@%s/%s", dbUser, dbPassword, dbAddress, dbDatabase)))
	assert.NoError(t, err)

	err = client.Connect(context.Background())
	assert.NoError(t, err)

	var db *mongo.Database
	// Giving some time for the DB to boot up
	retryCount := 0
	for {
		db = client.Database("hs_auth")
		err := client.Ping(context.Background(), nil)
		if err == nil {
			break
		} else if retryCount == 3 {
			fmt.Println(err)
			panic("could not connect to db")
		}
		retryCount++
		fmt.Println("could not connect to database, will retry in a bit")
		time.Sleep(5 * time.Second)
	}

	return db
}
