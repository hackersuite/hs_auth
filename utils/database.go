package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/unicsmcr/hs_auth/environment"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// NewDatabase creates a new connection to the database specified in given Env
func NewDatabase(logger *zap.Logger, env *environment.Env) (*mongo.Database, error) {
	connectionURL := fmt.Sprintf(`mongodb://%s:%s@%s/%s`,
		env.Get(environment.MongoUser),
		env.Get(environment.MongoPassword),
		env.Get(environment.MongoHost),
		env.Get(environment.MongoDatabase))

	logger.Info("db connection details",
		zap.String("user", env.Get(environment.MongoUser)),
		zap.String("password env var name", environment.MongoPassword),
		zap.String("host", env.Get(environment.MongoHost)),
		zap.String("database", env.Get(environment.MongoDatabase)))

	client, err := mongo.NewClient(options.Client().ApplyURI(connectionURL))
	if err != nil {
		logger.Error("could not connect to database", zap.Error(err))
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		logger.Error("could not connect to database", zap.Error(err))
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		logger.Error("could not connect to database", zap.Error(err))
		return nil, err
	}
	logger.Info("connected to database")

	return client.Database("hs_auth"), nil
}
