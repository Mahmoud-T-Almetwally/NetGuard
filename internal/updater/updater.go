package updater

import (
	"log"
	"net/http"
	"netguard/internal/repository"
)

const StevenBlackURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts"

func Update(db *repository.DomainDB) {
	log.Println("Checking for blocklist updates...")

	// 1. Get current version from DB
	currentETag := db.GetETag("stevenblack")

	// 2. Prepare Request with If-None-Match
	client := &http.Client{}
	req, _ := http.NewRequest("GET", StevenBlackURL, nil)
	if currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	// 3. Send Request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Update check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Println("Blocklist is already up to date (304).")
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("Failed to download blocklist. Status: %d", resp.StatusCode)
		return
	}

	log.Println("New update found. Starting sync...")
	newETag := resp.Header.Get("ETag")

	domainChan := make(chan repository.BlockedDomain, 2000)

	doneChan := make(chan int)

	go func() {
		count, err := db.StreamSync(domainChan, "stevenblack")
		if err != nil {
			log.Printf("DB Sync Error: %v", err)
			doneChan <- 0
		} else {
			doneChan <- count
		}
	}()

	repository.ParseAndStream(resp.Body, domainChan, "stevenblack")

	totalProcessed := <-doneChan

	if totalProcessed > 0 {
		log.Printf("Update complete. Active rules: %d", totalProcessed)
		if newETag != "" {
			db.UpdateETag("stevenblack", newETag)
		}
	} else {
		log.Println("Update processed, but zero rules were added/kept. Something might be wrong.")
	}
}
