package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
)

type healthResponse struct {
	Status    string `json:"status"`
	RequestID string `json:"requestId"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:    "ok",
		RequestID: uuid.NewString(),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)

	log.Printf("poc-app microservice listening on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
