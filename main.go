package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type heartbeatResponse struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", heartbeat)
	log.Fatal(http.ListenAndServe(":8080", router))
}

func heartbeat(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(heartbeatResponse{Status: "OK", Code: 200})
}

func SampleFunc(a, b int) int {
	return a + b
}
