// +build integration

package mongo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	repositories "github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"github.com/unicsmcr/hs_auth/utils/auth"
	authlevels "github.com/unicsmcr/hs_auth/utils/auth/common"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var (
	testJWTSecret     = "supersecret"
	testBaseAuthLevel = authlevels.Applicant

	testUser = entities.User{
		ID:        primitive.NewObjectID(),
		Name:      "Bob the Tester",
		Email:     "test@email.com",
		Password:  "password123",
		AuthLevel: testBaseAuthLevel,
		Team:      primitive.NewObjectID(),
	}
)

func setupUserTest(t *testing.T) (uService *mongoUserService, uRepo *repositories.UserRepository, cleanup func()) {
	db := testutils.ConnectToIntegrationTestDB(t)

	userRepository, err := repositories.NewUserRepository(db)
	if err != nil {
		panic(err)
	}

	resetEnv := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: testJWTSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	resetEnv()

	uService = &mongoUserService{
		logger: zap.NewNop(),
		cfg: &config.AppConfig{
			BaseAuthLevel: testBaseAuthLevel,
		},
		env:            env,
		userRepository: userRepository,
	}

	return uService, userRepository, func() {
		uRepo.Drop(context.Background())
	}
}

func Test_NewMongoUserService__should_return_non_nil_object(t *testing.T) {
	assert.NotNil(t, NewMongoUserService(nil, nil, nil, nil))
}

func Test_User_ErrInvalidID_should_be_returned_when_provided_id_is_invalid(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	tests := []struct {
		name         string
		testFunction func(id string) error
	}{
		{
			name: "GetUsersWithTeam",
			testFunction: func(id string) error {
				_, err := uService.GetUsersWithTeam(context.Background(), id)
				return err
			},
		},
		{
			name: "GetUserWithID",
			testFunction: func(id string) error {
				_, err := uService.GetUserWithID(context.Background(), id)
				return err
			},
		},
		{
			name: "UpdateUsersWithTeam",
			testFunction: func(id string) error {
				return uService.UpdateUsersWithTeam(context.Background(), id, services.UserUpdateParams{})
			},
		},
		{
			name: "UpdateUserWithID",
			testFunction: func(id string) error {
				return uService.UpdateUserWithID(context.Background(), id, services.UserUpdateParams{})
			},
		},
		{
			name: "DeleteUserWithID",
			testFunction: func(id string) error {
				return uService.DeleteUserWithID(context.Background(), id)
			},
		},
		{
			name: "ResetPasswordForUserWithIDAndEmail",
			testFunction: func(id string) error {
				return uService.ResetPasswordForUserWithIDAndEmail(context.Background(), id, "", "")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidID, tt.testFunction("invalid ID"))
		})
	}
}

func Test_User_ErrInvalidToken_should_be_returned_when_provided_JWT_is_invalid(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	tests := []struct {
		name         string
		testFunction func(jwt string) error
	}{
		{
			name: "GetUserWithJWT",
			testFunction: func(jwt string) error {
				_, err := uService.GetUserWithJWT(context.Background(), jwt)
				return err
			},
		},
		{
			name: "UpdateUserWithJWT",
			testFunction: func(jwt string) error {
				err := uService.UpdateUserWithJWT(context.Background(), jwt, nil)
				return err
			},
		},
		{
			name: "ResetPasswordForUserWithJWTAndEmail",
			testFunction: func(jwt string) error {
				err := uService.ResetPasswordForUserWithJWTAndEmail(context.Background(), jwt, "", "")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidToken, tt.testFunction("invalid token"))
		})
	}
}

func Test_CreateUser__should_return_ErrEmailTaken_when_email_is_taken(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	_, err := uRepo.InsertOne(context.Background(), testUser)
	assert.NoError(t, err)

	user, err := uService.CreateUser(context.Background(), testUser.Name, testUser.Email, testUser.Password)

	assert.Equal(t, services.ErrEmailTaken, err)
	assert.Nil(t, user)
}

func Test_CreateUser__should_create_correct_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	user, err := uService.CreateUser(context.Background(), testUser.Name, testUser.Email, testUser.Password)
	assert.NoError(t, err)

	assert.Equal(t, testUser.Name, user.Name)

	res := uRepo.FindOne(context.Background(), bson.M{
		string(entities.UserID):        user.ID,
		string(entities.UserEmail):     testUser.Email,
		string(entities.UserName):      testUser.Name,
		string(entities.UserAuthLevel): testBaseAuthLevel,
	})

	assert.NoError(t, res.Err())
}

func Test_GetUsers__should_return_expected_users(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	testUsers := []entities.User{testUser, testUser2}

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUsers[0], testUsers[1]})
	assert.NoError(t, err)

	users, err := uService.GetUsers(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, testUsers, users)
}

func Test_GetUsersWithTeam__should_return_expected_users(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"
	testUser3 := testUser
	testUser3.ID = primitive.NewObjectID()
	testUser3.Email = "test3@email.com"
	testUser3.Team = primitive.NewObjectID()

	usersInTeam1 := []entities.User{testUser, testUser2}

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2, testUser3})
	assert.NoError(t, err)

	users, err := uService.GetUsersWithTeam(context.Background(), testUser.Team.Hex())

	assert.NoError(t, err)
	assert.Equal(t, usersInTeam1, users)
}

func Test_GetUsersWithAuthLevel__should_return_expected_users(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"
	testUser3 := testUser
	testUser3.ID = primitive.NewObjectID()
	testUser3.Email = "test3@email.com"
	testUser3.AuthLevel = testUser.AuthLevel + 1

	expextedUsers := []entities.User{testUser, testUser2}

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2, testUser3})
	assert.NoError(t, err)

	users, err := uService.GetUsersWithAuthLevel(context.Background(), testBaseAuthLevel)

	assert.NoError(t, err)
	assert.Equal(t, expextedUsers, users)
}

func Test_GetUserWithID__should_return_error_when_user_with_id_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	user, err := uService.GetUserWithID(context.Background(), testUser.ID.Hex())

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, user)
}

func Test_GetUserWithID__should_return_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	user, err := uService.GetUserWithID(context.Background(), testUser.ID.Hex())

	assert.NoError(t, err)
	assert.Equal(t, testUser, *user)
}

func Test_GetUserWithEmail__should_return_error_when_user_with_email_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	user, err := uService.GetUserWithEmail(context.Background(), testUser.Email)

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, user)
}

func Test_GetUserWithEmail__should_return_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	user, err := uService.GetUserWithEmail(context.Background(), testUser.Email)

	assert.NoError(t, err)
	assert.Equal(t, testUser, *user)
}

func Test_GetUserWithEmailAndPwd__should_return_error_when_user_with_email_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	user, err := uService.GetUserWithEmailAndPwd(context.Background(), testUser.Email, "")

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, user)
}

func Test_GetUserWithEmailAndPwd__should_return_ErrNotFound_when_password_is_incorrect(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	_, err := uRepo.InsertOne(context.Background(), testUser)
	assert.NoError(t, err)

	user, err := uService.GetUserWithEmailAndPwd(context.Background(), testUser.Email, "")

	assert.Equal(t, services.ErrNotFound, err)
	assert.Nil(t, user)
}

func Test_GetUserWithEmailAndPwd__should_return_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	rawPwd := testUser.Password

	var err error
	testUser.Password, err = auth.GetHashForPassword(testUser.Password)

	_, err = uRepo.InsertOne(context.Background(), testUser)
	assert.NoError(t, err)

	user, err := uService.GetUserWithEmailAndPwd(context.Background(), testUser.Email, rawPwd)

	assert.NoError(t, err)
	assert.Equal(t, testUser, *user)
}

func Test_GetUserWithJWT__should_return_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	_, err := uRepo.InsertOne(context.Background(), testUser)
	assert.NoError(t, err)

	jwt, err := auth.NewJWT(testUser, 1000000000, time.Now().Unix(), auth.Auth, []byte(testJWTSecret))

	user, err := uService.GetUserWithJWT(context.Background(), jwt)

	assert.NoError(t, err)
	assert.Equal(t, testUser, *user)
}

func Test_UpdateUsersWithTeam__should_update_expected_users(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"
	testUser3 := testUser
	testUser3.ID = primitive.NewObjectID()
	testUser3.Email = "test3@email.com"
	testUser3.Team = primitive.NewObjectID()

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2, testUser3})
	assert.NoError(t, err)

	err = uService.UpdateUsersWithTeam(context.Background(), testUser.Team.Hex(), services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})

	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	testUser.Name = "Rob the tester"
	testUser2.Name = "Rob the tester"

	assert.Equal(t, []entities.User{testUser, testUser2, testUser3}, users)
}

func Test_UpdateUsersWithAuthLevel__should_update_expected_users(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"
	testUser3 := testUser
	testUser3.ID = primitive.NewObjectID()
	testUser3.Email = "test3@email.com"
	testUser3.AuthLevel = testUser.AuthLevel + 1

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2, testUser3})
	assert.NoError(t, err)

	err = uService.UpdateUsersWithAuthLevel(context.Background(), testUser.AuthLevel, services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})

	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	testUser.Name = "Rob the tester"
	testUser2.Name = "Rob the tester"

	assert.Equal(t, []entities.User{testUser, testUser2, testUser3}, users)
}

func Test_UpdateUserWithID__should_return_ErrNotFound_when_user_with_id_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	err := uService.UpdateUserWithID(context.Background(), testUser.ID.Hex(), services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_UpdateUserWithID__should_update_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	err = uService.UpdateUserWithID(context.Background(), testUser.ID.Hex(), services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})

	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	testUser.Name = "Rob the tester"

	assert.Equal(t, []entities.User{testUser, testUser2}, users)
}

func Test_UpdateUserWithEmail__should_return_ErrNotFound_when_user_with_id_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	err := uService.UpdateUserWithEmail(context.Background(), testUser.Email, services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_UpdateUserWithEmail__should_update_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	err = uService.UpdateUserWithEmail(context.Background(), testUser.Email, services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	testUser.Name = "Rob the tester"

	assert.Equal(t, []entities.User{testUser, testUser2}, users)
}

func Test_UpdateUserWithJWT__should_update_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	jwt, err := auth.NewJWT(testUser, 1000000000, time.Now().Unix(), auth.Auth, []byte(testJWTSecret))

	err = uService.UpdateUserWithJWT(context.Background(), jwt, services.UserUpdateParams{
		entities.UserName: "Rob the tester",
	})
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	testUser.Name = "Rob the tester"

	assert.Equal(t, []entities.User{testUser, testUser2}, users)
}

func Test_DeleteUserWithID__should_return_ErrNotFound_when_user_with_id_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	err := uService.DeleteUserWithID(context.Background(), testUser.ID.Hex())

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_DeleteUserWithID__should_delete_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	err = uService.DeleteUserWithID(context.Background(), testUser.ID.Hex())
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Equal(t, []entities.User{testUser2}, users)
}

func Test_DeleteUserWithEmail__should_return_ErrNotFound_when_user_with_email_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	err := uService.DeleteUserWithEmail(context.Background(), testUser.Email)

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_ResetPasswordForUserWithIDAndEmail__should_return_ErrNotFound_when_user_with_id_and_email_doesnt_exist(t *testing.T) {
	uService, _, cleanup := setupUserTest(t)
	defer cleanup()

	err := uService.ResetPasswordForUserWithIDAndEmail(context.Background(), testUser.ID.Hex(), testUser.Email, "")

	assert.Equal(t, services.ErrNotFound, err)
}

func Test_DeleteUserWithEmail__should_delete_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	err = uService.DeleteUserWithEmail(context.Background(), testUser.Email)
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Equal(t, []entities.User{testUser2}, users)
}

func Test_ResetPasswordForUserWithIDAndEmail__should_update_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	err = uService.ResetPasswordForUserWithIDAndEmail(context.Background(), testUser.ID.Hex(), testUser.Email, "password321")
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Equal(t, testUser.ID, users[0].ID)

	err = auth.CompareHashAndPassword(users[0].Password, "password321")
	assert.NoError(t, err)

	assert.Equal(t, testUser2, users[1])
}

func Test_ResetPasswordForUserWithJWTAndEmail__should_update_expected_user(t *testing.T) {
	uService, uRepo, cleanup := setupUserTest(t)
	defer cleanup()

	testUser2 := testUser
	testUser2.ID = primitive.NewObjectID()
	testUser2.Email = "test2@email.com"

	_, err := uRepo.InsertMany(context.Background(), []interface{}{testUser, testUser2})
	assert.NoError(t, err)

	jwt, err := auth.NewJWT(testUser, time.Now().Unix(), 1000000000, auth.Auth, []byte(testJWTSecret))
	assert.NoError(t, err)

	err = uService.ResetPasswordForUserWithJWTAndEmail(context.Background(), jwt, testUser.Email, "password321")
	assert.NoError(t, err)

	cur, err := uRepo.Find(context.Background(), bson.M{})
	assert.NoError(t, err)

	users, err := decodeUsersResult(context.Background(), cur)
	assert.NoError(t, err)

	assert.Equal(t, testUser.ID, users[0].ID)

	err = auth.CompareHashAndPassword(users[0].Password, "password321")
	assert.NoError(t, err)

	assert.Equal(t, testUser2, users[1])
}
