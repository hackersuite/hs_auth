package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type heartbeatResponse struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", heartbeat)

	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Fatal("could not start server: PORT env variable not set")
	}

	fmt.Printf("starting server on localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}

func heartbeat(w http.ResponseWriter, r *http.Request) {
	dbURL := os.Getenv("DB_URL")
	connectionURL := fmt.Sprintf("mongodb://%s", dbURL)
	fmt.Printf("connecting to database at %s\n", connectionURL)
	if len(dbURL) == 0 {
		log.Fatal("could not start server: DB_URL not defined")
	}

	clientOptions := options.Client().ApplyURI(connectionURL)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	client, err := mongo.Connect(ctx, clientOptions)
	defer client.Disconnect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("connection to database established!\n")

	json.NewEncoder(w).Encode(heartbeatResponse{Status: "OK", Code: 200})
}

// SampleFunc used only for testing out CI
func SampleFunc(a, b int) int {
	return a + b
}
