package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

type heartbeatResponse struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", heartbeat)
	port := os.Getenv("PORT")
	fmt.Printf("starting server on localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), router))
}

func heartbeat(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(heartbeatResponse{Status: "OK", Code: 200})
}

// SampleFunc used only for testing out CI
func SampleFunc(a, b int) int {
	return a + b
}
