package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/unicsmcr/hs_auth/entities"

	"gopkg.in/go-playground/validator.v9"

	"github.com/gorilla/mux"
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
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", heartbeat)

	validate := validator.New()

	user := entities.User{
		Name:     "hellow",
		Email:    "email@email.com",
		Password: "password",
	}

	err := validate.Struct(user)
	if err != nil {
		log.Fatal(err)
	}

	connectToDB()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	result, err := db.Collection("users").InsertOne(ctx, user)
	if err != nil {
		fmt.Println("user already exists")
	}
	log.Println(result)
	cancel()

	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Fatal("could not start server: PORT env variable not set")
	}

	fmt.Printf("starting server on localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
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
