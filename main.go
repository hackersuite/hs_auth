package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

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
	clientOptions := options.Client().ApplyURI("mongodb://mongo")

	// connect to DB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	defer client.Disconnect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	json.NewEncoder(w).Encode(heartbeatResponse{Status: "OK", Code: 200})
}

// SampleFunc used only for testing out CI
func SampleFunc(a, b int) int {
	return a + b
}
