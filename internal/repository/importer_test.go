package repository

import (
	"strings"
	"testing"
)

func TestParseAndStream(t *testing.T) {
	// Simulate a hosts file string
	rawFile := `
# This is a comment
127.0.0.1   localhost
0.0.0.0     adserver.com

# Another comment
0.0.0.0     malware.xyz
`
	reader := strings.NewReader(rawFile)
	outChan := make(chan BlockedDomain, 10)

	// Run in background
	go ParseAndStream(reader, outChan, "test")

	// Collect results
	var results []BlockedDomain
	for item := range outChan {
		results = append(results, item)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 domains, got %d", len(results))
	}
	if results[0].Domain != "localhost" {
		t.Errorf("Parsed wrong domain: %s", results[0].Domain)
	}
}