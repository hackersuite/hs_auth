package main

import (
	"fmt"
	"log"

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

	err = server.Run(fmt.Sprintf(":%s", server.Port))
	if err != nil {
		log.Fatal(fmt.Sprintf("could not start server: %s", err))
	}

	log.Printf("server started at: localhost:%s", server.Port)
	
}

