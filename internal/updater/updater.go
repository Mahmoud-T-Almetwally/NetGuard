package updater

import (
	"log"
	"net/http"
	"netguard/internal/config"
	"netguard/internal/repository"
	"sync"
)

// Run now accepts []config.SourceConfig
func Run(db *repository.DomainDB, sources []config.SourceConfig) {
	var wg sync.WaitGroup

	for _, src := range sources {
		wg.Add(1)
		// Pass the whole SourceConfig object
		go func(s config.SourceConfig) {
			defer wg.Done()
			processSource(db, s)
		}(src)
	}
	
	wg.Wait()
}

func processSource(db *repository.DomainDB, src config.SourceConfig) {
	log.Printf("Checking source: %s (%s)", src.Name, src.Format)

	// Use Name + URL to ensure unique ETag storage keys
	etagKey := src.Name + "_" + src.URL
	currentETag := db.GetETag(etagKey)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", src.URL, nil)
	if currentETag != "" {
		req.Header.Set("If-None-Match", currentETag)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching %s: %v", src.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Printf("[%s] Up to date.", src.Name)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("[%s] Failed with status %d", src.Name, resp.StatusCode)
		return
	}

	// Prepare pipeline
	domainChan := make(chan repository.BlockedDomain, 2000)
	doneChan := make(chan int)

	// DB Consumer: Note we pass src.Name here so the DB handles Mark-and-Sweep correctly
	go func() {
		count, err := db.StreamSync(domainChan, src.Name)
		if err != nil {
			log.Printf("DB Error %s: %v", src.Name, err)
			doneChan <- 0
		} else {
			doneChan <- count
		}
	}()

	// Producer: Pass the full 'src' config so Parser knows how to read it
	repository.ParseAndStream(resp.Body, domainChan, src)
	
	count := <-doneChan
	log.Printf("[%s] Updated. %d rules active.", src.Name, count)
	
	if newETag := resp.Header.Get("ETag"); newETag != "" {
		db.UpdateETag(etagKey, newETag)
	}
}