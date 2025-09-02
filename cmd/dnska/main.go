package main

import (
	"log"

	"github.com/vadim-su/dnska/internal/server"
)

func main() {
	srv, err := server.New()
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
