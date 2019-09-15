package testutils

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/mongo"
)

// SetEnvVars sets given environment variables and provides a callback function to restore the variables to their initial values
func SetEnvVars(vars map[string]string) (restoreVars func()) {
	initialValues := map[string]string{}
	unsetVars := map[string]bool{}

	for name, value := range vars {
		initialValue, exists := os.LookupEnv(name)
		if exists {
			initialValues[name] = initialValue
		} else {
			unsetVars[name] = true
		}

		err := os.Setenv(name, value)
		if err != nil {
			panic(err)
		}
	}

	return func() {
		for name, value := range initialValues {
			err := os.Setenv(name, value)
			if err != nil {
				panic(err)
			}
		}

		for name := range unsetVars {
			err := os.Unsetenv(name)
			if err != nil {
				panic(err)
			}
		}
	}
}

// UnsetVars unsets given environment variables and provides a callback function to restore the variables to their initial values
func UnsetVars(vars ...string) (restoreVars func()) {
	initialValues := map[string]string{}
	for _, name := range vars {
		initialValue, exists := os.LookupEnv(name)
		if exists {
			initialValues[name] = initialValue
		}

		err := os.Unsetenv(name)
		if err != nil {
			panic(err)
		}
	}

	return func() {
		for name, value := range initialValues {
			err := os.Setenv(name, value)
			if err != nil {
				panic(err)
			}
		}
	}
}

// RouterGroupMatcher matches gin router groups with given path
type RouterGroupMatcher struct {
	// Path is the base path of the router groups to match
	Path string
}

// Matches implements the gomock.Matcher interface
func (r RouterGroupMatcher) Matches(x interface{}) bool {
	val := reflect.ValueOf(x)
	if reflect.Zero(reflect.TypeOf(x)) == val {
		return false
	}
	// fetching reference to BasePath
	basePathMethod := val.MethodByName("BasePath")
	if reflect.Zero(reflect.TypeOf(basePathMethod)) == basePathMethod {
		return false
	}
	// calling BasePath
	values := basePathMethod.Call([]reflect.Value{})
	if len(values) != 1 {
		return false
	}
	// checking if value is string
	if !values[0].Type().AssignableTo(reflect.TypeOf("")) {
		return false
	}

	if values[0].String() != r.Path {
		return false
	}
	return true
}

func (r RouterGroupMatcher) String() string {
	return fmt.Sprintf("router group's base path is %s", r.Path)
}

// ConnectToIntegrationTestDB waits for the integrations tests DB to become available
// and returns a connection to the DB
func ConnectToIntegrationTestDB(t *testing.T) *mongo.Database {
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
