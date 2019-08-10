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

func NewDatabase(logger *zap.Logger, env *environment.Env) *mongo.Database {
	connectionURL := fmt.Sprintf(`mongodb://%s:%s@%s/%s`,
		env.Get(environment.MongoUser),
		env.Get(environment.MongoPassword),
		env.Get(environment.MongoHost),
		env.Get(environment.MongoDatabase))

	client, err := mongo.NewClient(options.Client().ApplyURI(connectionURL))
	if err != nil {
		logger.Fatal("could not connect to database", zap.Error(err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		logger.Fatal("could not connect to database", zap.Error(err))
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		logger.Fatal("could not connect to database", zap.Error(err))
	}
	logger.Info("connected to database")

	return client.Database("hs_auth")
}
