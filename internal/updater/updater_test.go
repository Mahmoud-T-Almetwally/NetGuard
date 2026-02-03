package updater

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netguard/internal/config"
	"netguard/internal/repository"
)

func setupTestDB(t *testing.T) *repository.DomainDB {
	// Create a temp directory that automatically deletes after test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_netguard.db")

	db := &repository.DomainDB{}
	
	// InitDB will create the file and set WAL mode
	if err := db.InitDB(dbPath); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}
	
	return db
}

func TestRun_Integration(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulating ETag Logic
		if r.Header.Get("If-None-Match") == "v1.0" {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", "v1.0")
		w.WriteHeader(http.StatusOK)
		
		// Return a fake CSV file
		w.Write([]byte(`id,malicious_url
100,virus.test
101,trojan.test`))
	}))
	defer mockServer.Close()

	// 2. Setup In-Memory Database
	db := setupTestDB(t)

	// 3. Define Config pointing to Mock Server
	sources := []config.SourceConfig{
		{
			Name:         "test_feed",
			URL:          mockServer.URL, // Point to localhost mock
			Format:       "csv",
			TargetColumn: "malicious_url",
		},
	}

	// --- TEST PASS 1: Initial Download ---
	t.Log("Running Pass 1 (Fresh Download)...")
	Run(db, sources)

	// Verify Data in DB
	// We need a helper or custom query here since we filtered GetBlocklist to only BLOCK
	// But let's assume GetBlocklist works for blocked items
	list, err := db.GetBlocklist()
	if err != nil {
		t.Fatalf("DB Error: %v", err)
	}

	if len(list) != 2 {
		t.Errorf("Pass 1: Expected 2 domains, got %d", len(list))
	}

	// Verify ETag was saved
	savedTag := db.GetETag("test_feed_" + mockServer.URL)
	if savedTag != "v1.0" {
		t.Errorf("Pass 1: Expected ETag 'v1.0', got '%s'", savedTag)
	}

	// --- TEST PASS 2: Cached (304 Not Modified) ---
	t.Log("Running Pass 2 (Should be Cached)...")
	
	// If the logic works, this runs, server returns 304, DB is NOT touched/wiped
	Run(db, sources)

	listAfter, _ := db.GetBlocklist()
	if len(listAfter) != 2 {
		t.Errorf("Pass 2: DB corrupted after 304. Expected 2 domains, got %d", len(listAfter))
	}
}

// TestMultiSource ensures two sources don't overwrite each other
func TestRun_MultiSource(t *testing.T) {
	// Mock Server 1 (Hosts)
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 host1.com"))
	}))
	defer srv1.Close()

	// Mock Server 2 (Text)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("host2.com"))
	}))
	defer srv2.Close()

	db := setupTestDB(t)

	sources := []config.SourceConfig{
		{Name: "source_a", URL: srv1.URL, Format: "hosts"},
		{Name: "source_b", URL: srv2.URL, Format: "text"},
	}

	Run(db, sources)

	// We expect 2 domains total
	list, _ := db.GetBlocklist()
	if len(list) != 2 {
		t.Errorf("Expected 2 total domains from mixed sources, got %d", len(list))
	}
}