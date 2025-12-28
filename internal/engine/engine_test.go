package engine

import (
	"sync"
	"testing"
)

// TestBasicBlocking verifies the reverse trie logic
func TestBasicBlocking(t *testing.T) {
	trie := NewDomainTrie()
	
	// Setup rules
	domains := []string{"google.com", "ads.example.com"}
	trie.BulkInsert(domains)

	tests := []struct {
		input    string
		want     bool
		desc     string
	}{
		{"google.com", true, "Exact match"},
		{"analytics.google.com", true, "Subdomain match (Wildcard behavior)"},
		{"notgoogle.com", false, "Suffix match but different domain"},
		{"ads.example.com", true, "Exact subdomain match"},
		{"safe.example.com", false, "Sibling subdomain (should be safe)"},
		{"com", false, "Top level domain (should be safe)"},
		{"", false, "Empty string"},
	}

	for _, tc := range tests {
		got := trie.ShouldBlock(tc.input)
		if got != tc.want {
			t.Errorf("%s: Input '%s', want %v, got %v", tc.desc, tc.input, tc.want, got)
		}
	}
}

// TestConcurrency ensures the Engine doesn't crash (panic) when 
// updated and read simultaneously by hundreds of goroutines.
// Run with: go test -race ./internal/engine
func TestConcurrency(t *testing.T) {
	trie := NewDomainTrie()
	trie.Insert("initial.com")

	var wg sync.WaitGroup

	// Simulate 100 readers (Packet Listeners)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				trie.ShouldBlock("initial.com")
				trie.ShouldBlock("random.com")
			}
		}()
	}

	// Simulate 1 Writer (Updater)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			trie.Insert("new-rule.com")
		}
	}()

	wg.Wait()
}

// TestUninitializedEngine checks fault tolerance if Init() wasn't called
func TestUninitializedEngine(t *testing.T) {
	e := &Engine{} // No domainTrie created
	
	_, err := e.Decision("google.com")
	if err == nil {
		t.Error("Expected error when using uninitialized engine, got nil")
	}
}