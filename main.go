package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/unicsmcr/hs_auth/routers"

	"github.com/gin-gonic/gin"

	"go.uber.org/zap"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/entities"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type heartbeatResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var db *mongo.Database

func main() {
	var logger *zap.Logger
	var err error
	if os.Getenv("ENVIRONMENT") == "prod" {
		logger, err = zap.NewProduction()
	} else {
		logger, err = zap.NewDevelopment()
	}
	if err != nil {
		log.Fatalf("could not make zap logger: %s", err)
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		logger.Fatal("could not start server", zap.String("error", "PORT env variable not set"))
	}

	r := gin.Default()
	routers.RegisterRoutes(logger, r.Group(""))

	logger.Info("starting server", zap.String("address", fmt.Sprintf("localhost:%s", port)))
	err = r.Run(fmt.Sprintf(":%s", port))
	if err != nil {
		logger.Fatal("could not start server", zap.Error(err))
	}
}

func connectToDB() {
	connectionURL := fmt.Sprintf(`mongodb://%s:%s@%s/%s`, os.Getenv("MONGO_USER"), os.Getenv("MONGO_PASSWORD"), os.Getenv("MONGO_HOST"), os.Getenv("MONGO_DATABASE"))

	client, err := mongo.NewClient(options.Client().ApplyURI(connectionURL))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("connection to database established!\n")

	db = client.Database("hs_auth")
}

func heartbeat(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("request received from %s\n", r.RemoteAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	users, err := getUsers(ctx)
	if err != nil {
		json.NewEncoder(w).Encode(heartbeatResponse{Status: "ERROR", Code: 503, Message: err.Error()})
		return
	}

	// Encoding users to JSON
	jsonUsers, err := json.Marshal(users)
	if err != nil {
		json.NewEncoder(w).Encode(heartbeatResponse{Status: "ERROR", Code: 503, Message: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(heartbeatResponse{Status: "OK", Code: 200, Message: string(jsonUsers)})
}

func getUsers(ctx context.Context) ([]entities.User, error) {
	users := []entities.User{}

	// Executing query
	cur, err := db.Collection("users").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	// Decoding result
	for cur.Next(ctx) {
		var user entities.User
		err = cur.Decode(&user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// SampleFunc used only for testing out CI
func SampleFunc(a, b int) int {
	return a + b
}
