package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/entities"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/repositories"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/mongo"
)

type errTestCase struct {
	name           string
	id             string
	email          string
	password       string
	fieldsToUpdate map[string]interface{}
	prep           func(repo repositories.UserRepository)
	wantErr        error
}

func setupTest(t *testing.T) (repositories.UserRepository, UserService) {
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

	userRepository := repositories.NewUserRepository(db)
	userService := NewUserService(zap.NewNop(), userRepository)

	err = userRepository.Drop(context.Background())
	assert.NoError(t, err)

	return userRepository, userService
}

func Test_GetUserWithID__should_return_correct_user(t *testing.T) {
	uRepo, uService := setupTest(t)

	testID, err := primitive.ObjectIDFromHex("2134abd12312312321312313")
	assert.NoError(t, err)

	testUser := entities.User{
		Email: "john@doe.com",
		ID:    testID,
	}

	_, err = uRepo.InsertOne(context.Background(), testUser)
	defer uRepo.DeleteOne(context.Background(), bson.M{
		"_id": testUser.ID,
	})
	assert.NoError(t, err)

	user, err := uService.GetUserWithID(context.Background(), testID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, testUser, *user)
}

func Test_GetUserWithEmail__should_return_correct_user(t *testing.T) {
	uRepo, uService := setupTest(t)

	testID, err := primitive.ObjectIDFromHex("2134abd12312312321312313")
	assert.NoError(t, err)

	testUser := entities.User{
		Email: "john@doe.com",
		ID:    testID,
	}

	_, err = uRepo.InsertOne(context.Background(), testUser)
	defer uRepo.DeleteOne(context.Background(), bson.M{
		"_id": testUser.ID,
	})
	assert.NoError(t, err)

	user, err := uService.GetUserWithEmail(context.Background(), testUser.Email)
	assert.NoError(t, err)

	assert.Equal(t, testUser, *user)
}

func Test_GetUsers__should_return_correct_users(t *testing.T) {
	uRepo, uService := setupTest(t)

	testUsers := []entities.User{
		{
			ID:    primitive.NewObjectID(),
			Email: "john@doe.com",
		},
		{
			ID:    primitive.NewObjectID(),
			Email: "jane@doe.com",
		},
	}

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUsers[0], testUsers[1]})
	assert.NoError(t, err)

	users, err := uService.GetUsers(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, testUsers, users)
}

func Test_UpdateUserWithID__should_not_return_error_when_fields_to_update_is_empty(t *testing.T) {
	_, uService := setupTest(t)

	err := uService.UpdateUserWithID(context.Background(), "2134abd12312312321312313", nil)

	assert.NoError(t, err)
}

func Test_UpdateUserWithID__should_update_correct_user(t *testing.T) {
	uRepo, uService := setupTest(t)

	testID, err := primitive.ObjectIDFromHex("2134abd12312312321312313")
	assert.NoError(t, err)

	testUser := entities.User{
		Email: "john@doe.com",
		ID:    testID,
	}

	_, err = uRepo.InsertOne(context.Background(), testUser)
	defer uRepo.DeleteOne(context.Background(), bson.M{
		"_id": testUser.ID,
	})
	assert.NoError(t, err)

	testUser.Email = "jane@doe.com"

	err = uService.UpdateUserWithID(context.Background(), testID.Hex(), map[string]interface{}{
		"email": testUser.Email,
	})
	assert.NoError(t, err)

	updatedUser, err := uService.GetUserWithID(context.Background(), testID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, testUser, *updatedUser)
}

func Test_GetUserWithID__should_return_error(t *testing.T) {
	tests := []errTestCase{
		{
			name:    "when given id is invalid",
			wantErr: ErrInvalidID,
		},
		{
			name:    "when user with given id doesn't exist",
			id:      "2134abd12312312321312313",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupTest(t)
			if tt.prep != nil {
				tt.prep(uRepo)
			}

			_, err := uService.GetUserWithID(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func Test_GetUserWithEmail__should_return_error(t *testing.T) {
	tests := []errTestCase{
		{
			name:    "when user with given email doesn't exist",
			email:   "john@doe.com",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupTest(t)
			if tt.prep != nil {
				tt.prep(uRepo)
			}

			_, err := uService.GetUserWithEmail(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func Test_UpdateUserWithID__should_return_error(t *testing.T) {
	tests := []errTestCase{
		{
			name:    "when given id is invalid",
			id:      "2134abd1231231",
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupTest(t)
			if tt.prep != nil {
				tt.prep(uRepo)
			}

			err := uService.UpdateUserWithID(context.Background(), tt.id, tt.fieldsToUpdate)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
		})
	}
}
