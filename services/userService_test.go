// +build integration

package services

import (
	"context"
	"testing"

	"github.com/unicsmcr/hs_auth/testutils"

	"go.mongodb.org/mongo-driver/bson"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicsmcr/hs_auth/entities"

	"go.uber.org/zap"

	"github.com/unicsmcr/hs_auth/repositories"

	"github.com/stretchr/testify/assert"
)

type errUserTestCase struct {
	id             string
	name           string
	email          string
	password       string
	fieldsToUpdate map[string]interface{}
	prep           func(t *testing.T, repo repositories.UserRepository)
	wantErr        error
}

func setupUserTest(t *testing.T) (repositories.UserRepository, UserService) {
	db := testutils.ConnectToIntegrationTestDB(t)

	userRepository, err := repositories.NewUserRepository(db)
	if err != nil {
		panic(err)
	}
	userService := NewUserService(zap.NewNop(), userRepository)

	err = userRepository.Drop(context.Background())
	assert.NoError(t, err)

	return userRepository, userService
}

func Test_GetUserWithID__should_return_correct_user(t *testing.T) {
	uRepo, uService := setupUserTest(t)

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
	uRepo, uService := setupUserTest(t)

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
	uRepo, uService := setupUserTest(t)

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
	_, uService := setupUserTest(t)

	err := uService.UpdateUserWithID(context.Background(), "2134abd12312312321312313", nil)

	assert.NoError(t, err)
}

func Test_UpdateUserWithID__should_update_correct_user(t *testing.T) {
	uRepo, uService := setupUserTest(t)

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

func Test_CreateUser__should_create_required_user(t *testing.T) {
	_, uService := setupUserTest(t)

	testUser := entities.User{
		Name:      "John Doe",
		Email:     "john@doe.com",
		Password:  "password123",
		AuthLevel: 3,
	}

	createdUser, err := uService.CreateUser(context.Background(), testUser.Name, testUser.Email, testUser.Password, testUser.AuthLevel)
	assert.NoError(t, err)

	testUser.ID = createdUser.ID
	assert.Equal(t, testUser, *createdUser)

	userOnDB, err := uService.GetUserWithID(context.Background(), testUser.ID.Hex())
	assert.NoError(t, err)

	assert.Equal(t, testUser, *userOnDB)
}

func Test_DeleteUserWithEmail__should_delete_required_user(t *testing.T) {
	_, uService := setupUserTest(t)

	testUser := entities.User{
		Name:      "John Doe",
		Email:     "john@doe.com",
		Password:  "password123",
		AuthLevel: 3,
	}

	_, err := uService.CreateUser(context.Background(), testUser.Name, testUser.Email, testUser.Password, testUser.AuthLevel)
	assert.NoError(t, err)

	err = uService.DeleteUserWithEmail(context.Background(), testUser.Email)
	assert.NoError(t, err)

	_, err = uService.GetUserWithEmail(context.Background(), testUser.Email)
	assert.Error(t, err)

	assert.Equal(t, ErrNotFound, err)
}

func Test_UpdateUsersWithTeam__should_update_required_users(t *testing.T) {
	uRepo, uService := setupUserTest(t)
	defer uRepo.Drop(context.Background())

	testTeamID := primitive.NewObjectID()

	testUsers := []entities.User{
		{
			ID:   primitive.NewObjectID(),
			Name: "John Doe",
			Team: testTeamID,
		},
		{
			ID:   primitive.NewObjectID(),
			Name: "Jane Doe",
			Team: testTeamID,
		},
		{
			ID:   primitive.NewObjectID(),
			Name: "Bob Builder",
			Team: primitive.NewObjectID(),
		},
	}

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUsers[0], testUsers[1], testUsers[2]})
	assert.NoError(t, err)

	err = uService.UpdateUsersWithTeam(context.Background(), testTeamID.Hex(), map[string]interface{}{
		"auth_level": 3,
	})
	assert.NoError(t, err)

	testUsers[0].AuthLevel = 3
	testUsers[1].AuthLevel = 3

	users, err := uService.GetUsers(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, testUsers, users)
}

func Test_GetUserWithID__should_return_error(t *testing.T) {
	tests := []errUserTestCase{
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
			uRepo, uService := setupUserTest(t)
			if tt.prep != nil {
				tt.prep(t, uRepo)
			}

			_, err := uService.GetUserWithID(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
			uRepo.Drop(context.Background())
		})
	}
}

func Test_GetUserWithEmail__should_return_error(t *testing.T) {
	tests := []errUserTestCase{
		{
			name:    "when user with given email doesn't exist",
			email:   "john@doe.com",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupUserTest(t)
			if tt.prep != nil {
				tt.prep(t, uRepo)
			}

			_, err := uService.GetUserWithEmail(context.Background(), tt.id)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
			uRepo.Drop(context.Background())
		})
	}
}

func Test_UpdateUsersWithTeam__should_return_error(t *testing.T) {
	tests := []errUserTestCase{
		{
			name:    "when given id is invalid",
			id:      "2134abd1231231",
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupUserTest(t)
			if tt.prep != nil {
				tt.prep(t, uRepo)
			}

			err := uService.UpdateUsersWithTeam(context.Background(), tt.id, tt.fieldsToUpdate)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
			uRepo.Drop(context.Background())
		})
	}
}

func Test_UpdateUserWithID__should_return_error(t *testing.T) {
	tests := []errUserTestCase{
		{
			name:    "when given id is invalid",
			id:      "2134abd1231231",
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uRepo, uService := setupUserTest(t)
			if tt.prep != nil {
				tt.prep(t, uRepo)
			}

			err := uService.UpdateUserWithID(context.Background(), tt.id, tt.fieldsToUpdate)
			assert.Error(t, err)

			assert.Equal(t, tt.wantErr, err)
			uRepo.Drop(context.Background())
		})
	}
}
