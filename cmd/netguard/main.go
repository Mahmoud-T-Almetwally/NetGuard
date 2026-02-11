package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netguard/internal/engine"
	"netguard/internal/packet"
	"netguard/internal/repository"
	"netguard/internal/updater"
	"netguard/internal/inference"
	"netguard/internal/analysis"
	"netguard/internal/config"

	"github.com/florianl/go-nfqueue"
)

func main() {

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Configuration loaded. Log Level: %s", cfg.App.LogLevel)

	db := &repository.DomainDB{}
	if err := db.InitDB("./data/blocklist.db"); err != nil {
		log.Fatalf("Fatal: Could not Initialize database: %v", err)
	}
	log.Println("Database Initialized Successfully.")

	log.Println("Checking for updates...")
	updater.Run(db, cfg.Blocking.Sources)
	
    if err := inference.InitONNX(); err != nil {
		log.Printf("ONNX Init Failed: %v", err)
		log.Println("Running in Database-Only mode.")
	} else {
		defer inference.CleanupONNX()
	}

    pred, err := inference.NewPredictor("./data/models")
    if err != nil {
		log.Printf("Models not found: %v", err)
		log.Println("Running in Database-Only mode.")
		pred = nil 
	} else {
		log.Println("Models Loaded.")
		defer pred.Close()
	}

	scanner := analysis.NewScanner(db, pred)

	eng := &engine.Engine{}
	if err := eng.Init(db, scanner); err != nil{
		log.Fatalf("Fatal: Could not Initialize engine: %v", err)
	}
	log.Println("Engine Initialized Successfully.")
	
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	config := nfqueue.Config{
		NfQueue:      0,                 		
		MaxPacketLen: 0xFFFF,            		
		MaxQueueLen:  0xFF,              		
		Copymode:     nfqueue.NfQnlCopyPacket,  
		WriteTimeout: 15 * time.Millisecond,
	}

	listener := packet.Listener{}

	go func() {
		log.Println("Starting NFQueue listener on Queue 0...")
		if err := listener.Start(ctx, eng, config); err != nil {
			log.Printf("Listener stopped with error: %v", err)
			cancel()
		}
	}()

	log.Println("Starting NFQueue listener...")

	log.Println("NetGuard is running. Press CTRL+C to stop.")
	<-sigChan

	log.Println("\nReceived shutdown signal. Stopping listener...")
	cancel() 
	
	time.Sleep(1 * time.Second) 
	log.Println("Exiting.")
}
