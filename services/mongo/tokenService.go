package mongo

import (
	"context"
	"github.com/unicsmcr/hs_auth/entities"
	"github.com/unicsmcr/hs_auth/environment"
	"github.com/unicsmcr/hs_auth/repositories"
	"github.com/unicsmcr/hs_auth/services"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type mongoTokenService struct {
	logger          *zap.Logger
	env             *environment.Env
	tokenRepository *repositories.TokenRepository
}

// NewMongoTokenService creates a new TokenService that uses MongoDB as the storage technology
func NewMongoTokenService(logger *zap.Logger, env *environment.Env, tokenRepository *repositories.TokenRepository) services.TokenService {
	return &mongoTokenService{
		logger:          logger,
		env:             env,
		tokenRepository: tokenRepository,
	}
}

func (s *mongoTokenService) AddServiceToken(ctx context.Context, tokenId primitive.ObjectID, creatorID, jwt string) (*entities.Token, error) {
	creatorMongoID, err := primitive.ObjectIDFromHex(creatorID)
	if err != nil {
		return nil, services.ErrInvalidID
	}

	token := &entities.Token{
		ID:      tokenId,
		JWT:     jwt,
		Creator: creatorMongoID,
	}

	_, err = s.tokenRepository.InsertOne(ctx, *token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *mongoTokenService) DeleteServiceToken(ctx context.Context, id string) error {
	mongoID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return services.ErrInvalidID
	}

	res, err := s.tokenRepository.DeleteOne(ctx, bson.M{
		string(entities.TokenID): mongoID,
	})

	if err != nil {
		return err
	} else if res.DeletedCount == 0 {
		return services.ErrNotFound
	}

	return nil
}
