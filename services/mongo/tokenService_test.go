// +build integration

package mongo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"github.com/unicsmcr/hs_auth/testutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

var (
	testToken = entities.ServiceToken{
		ID:      primitive.NewObjectID(),
		JWT:     "test_token",
		Creator: primitive.NewObjectID(),
	}
)

type tokenTestSetup struct {
	tService *mongoTokenService
	tRepo    *repositories.TokenRepository
	cleanup  func()
}

func setupTokenTest(t *testing.T) *tokenTestSetup {
	db := testutils.ConnectToIntegrationTestDB(t)

	tRepo, err := repositories.NewTokenRepository(db)
	if err != nil {
		panic(err)
	}

	resetEnv := testutils.SetEnvVars(map[string]string{
		environment.JWTSecret: testJWTSecret,
	})
	env := environment.NewEnv(zap.NewNop())
	resetEnv()

	tService := &mongoTokenService{
		logger:          zap.NewNop(),
		env:             env,
		tokenRepository: tRepo,
	}

	return &tokenTestSetup{
		tService: tService,
		tRepo:    tRepo,
		cleanup: func() {
			tRepo.Drop(context.Background())
		},
	}
}

func Test_NewMongoTokenService__should_return_non_nil_object(t *testing.T) {
	assert.NotNil(t, NewMongoTokenService(nil, nil, nil))
}

func Test_Token_ErrInvalidID_should_be_returned_when_provided_id_is_invalid(t *testing.T) {
	setup := setupTokenTest(t)
	defer setup.cleanup()

	tests := []struct {
		name         string
		testFunction func(id string) error
	}{
		{
			name: "AddServiceToken",
			testFunction: func(id string) error {
				_, err := setup.tService.CreateServiceToken(context.Background(), id, "")
				return err
			},
		},
		{
			name: "DeleteServiceToken",
			testFunction: func(id string) error {
				err := setup.tService.DeleteServiceToken(context.Background(), id)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, services.ErrInvalidID, tt.testFunction("invalid ID"))
		})
	}
}

func Test_CreateServiceToken__should_return_expected_token(t *testing.T) {
	setup := setupTokenTest(t)
	defer setup.cleanup()

	token, err := setup.tService.CreateServiceToken(context.Background(), testToken.Creator.Hex(), testToken.JWT)
	assert.NoError(t, err)
	assert.Equal(t, testToken.JWT, token.JWT)

	res := setup.tRepo.FindOne(context.Background(), bson.M{
		string(entities.ServiceTokenCreator): testToken.Creator,
		string(entities.ServiceTokenJWT):     testToken.JWT,
	})
	assert.NoError(t, res.Err())
}

func Test_DeleteServiceToken__should_return_ErrNotFound_when_token_not_found(t *testing.T) {
	setup := setupTokenTest(t)
	defer setup.cleanup()

	err := setup.tService.DeleteServiceToken(context.Background(), testToken.ID.Hex())

	assert.Error(t, services.ErrNotFound, err)
}

func Test_DeleteServiceToken__should_return_nil_error_when_deleted_token(t *testing.T) {
	setup := setupTokenTest(t)
	defer setup.cleanup()

	_, err := setup.tRepo.InsertOne(context.Background(), testToken)
	assert.NoError(t, err)

	err = setup.tService.DeleteServiceToken(context.Background(), testToken.ID.Hex())

	assert.Error(t, services.ErrNotFound, err)
}
