package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vadim-su/dnska/internal/config"
	"github.com/vadim-su/dnska/internal/server"
)

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "dnska.yaml", "Configuration file path")
	flag.StringVar(&configFile, "c", "dnska.yaml", "Configuration file path (shorthand)")
	flag.Parse()

	var cfg *config.Config
	var err error

	// If no config file specified, try default location

	absPath, _ := filepath.Abs(configFile)
	cfg, err = config.LoadFromFile(configFile)
	if err != nil {
		log.Printf("Failed to load config from %s: %v, using defaults", absPath, err)
		cfg = config.DefaultConfig()
	} else {
		log.Printf("Loaded configuration from %s", absPath)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		if err := srv.Close(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}

	log.Println("Server stopped")
}
