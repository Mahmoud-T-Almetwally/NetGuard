package repository

import (
	"testing"
)

func TestStreamSync(t *testing.T) {
	// 1. Setup In-Memory DB
	db := &DomainDB{}
	if err := db.InitDB(":memory:"); err != nil {
		t.Fatalf("Failed to init DB: %v", err)
	}

	// 2. Pre-populate DB with "Old" data
	// We manually insert a domain that should be removed later
	tx, _ := db.db.Begin()
	tx.Exec("INSERT INTO rules (domain, source, batch_id) VALUES (?, ?, ?)", "old-entry.com", "stevenblack", 100)
	tx.Exec("INSERT INTO rules (domain, source, batch_id) VALUES (?, ?, ?)", "keep-me.com", "stevenblack", 100)
	tx.Commit()

	// 3. Prepare the "New" data stream
	// 'old-entry.com' is missing (should be deleted)
	// 'keep-me.com' is present (should be updated)
	// 'new-entry.com' is new (should be inserted)
	stream := make(chan BlockedDomain, 5)
	go func() {
		stream <- BlockedDomain{Domain: "keep-me.com", Action: "BLOCK"}
		stream <- BlockedDomain{Domain: "new-entry.com", Action: "BLOCK"}
		close(stream)
	}()

	// 4. Run Sync
	count, err := db.StreamSync(stream, "stevenblack")
	if err != nil {
		t.Fatalf("StreamSync failed: %v", err)
	}

	// 5. Assertions
	if count != 2 {
		t.Errorf("Expected 2 processed items, got %d", count)
	}

	// Check total rows in DB
	rows, _ := db.GetAll()
	
	// Convert slice to map for easy checking
	lookup := make(map[string]bool)
	for _, r := range rows {
		lookup[r] = true
	}

	if lookup["old-entry.com"] {
		t.Error("Fault: 'old-entry.com' should have been deleted (Sweep phase failed)")
	}
	if !lookup["new-entry.com"] {
		t.Error("Fault: 'new-entry.com' should have been inserted")
	}
	if !lookup["keep-me.com"] {
		t.Error("Fault: 'keep-me.com' should have been preserved")
	}
}