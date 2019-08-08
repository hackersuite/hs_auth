package main

import (
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
)

type heartbeatResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var db *mongo.Database

func main() {
	server, err := InitializeServer()
	if err != nil {
		log.Fatal(fmt.Sprintf("could not create server: %s", err))
	}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		log.Fatalf("could not start server: %s", err)
	}

	err = server.Run(fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatal(fmt.Sprintf("could not start server: %s", err))
	}

	log.Printf("server started at: localhost:%s", port)
}
