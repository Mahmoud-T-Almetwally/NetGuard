package repository

import (
	"netguard/internal/config"
	"strings"
	"testing"
)

func TestParseAndStream_Formats(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		sourceConfig   config.SourceConfig
		expectedCount  int
		expectedDomain string // Check one domain to verify correct parsing
	}{
		{
			name: "Standard Hosts File",
			input: `
# Comment
127.0.0.1	localhost
0.0.0.0		ads.google.com
0.0.0.0		tracking.facebook.com
`,
			sourceConfig: config.SourceConfig{
				Name:   "steven_black",
				Format: "hosts",
			},
			expectedCount:  3,
			expectedDomain: "ads.google.com",
		},
		{
			name: "Text File (Raw List)",
			input: `
# Blocklist
malware.xyz
bad-crypto.com
`,
			sourceConfig: config.SourceConfig{
				Name:   "simple_list",
				Format: "text",
			},
			expectedCount:  2,
			expectedDomain: "malware.xyz",
		},
		{
			name: "CSV - Target Column 1",
			input: `id,url,threat
1,phishing.com,high
2,virus.org,critical`,
			sourceConfig: config.SourceConfig{
				Name:         "threat_feed",
				Format:       "csv",
				TargetColumn: "url",
			},
			expectedCount:  2,
			expectedDomain: "phishing.com",
		},
		{
			name: "CSV - Target Column Last (Mixed Caps)",
			input: `ID,DATE,DOMAIN_NAME
101,2023-01-01,badstuff.net
102,2023-01-01,worse.com`,
			sourceConfig: config.SourceConfig{
				Name:         "mixed_caps",
				Format:       "csv",
				TargetColumn: "domain_name", // Should match DOMAIN_NAME case-insensitively
			},
			expectedCount:  2,
			expectedDomain: "badstuff.net",
		},
		{
			name: "CSV - Missing Column (Fault Tolerance)",
			input: `id,date,ip
1,now,1.1.1.1`,
			sourceConfig: config.SourceConfig{
				Name:         "broken_csv",
				Format:       "csv",
				TargetColumn: "url", // Does not exist
			},
			expectedCount: 0, // Should handle gracefully
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup Reader and Channel
			reader := strings.NewReader(tc.input)
			outChan := make(chan BlockedDomain, 10)

			// 2. Run Parser in background
			go ParseAndStream(reader, outChan, tc.sourceConfig)

			// 3. Collect Results
			var results []BlockedDomain
			for item := range outChan {
				results = append(results, item)
			}

			// 4. Assertions
			if len(results) != tc.expectedCount {
				t.Errorf("Expected %d domains, got %d", tc.expectedCount, len(results))
			}

			if tc.expectedCount > 0 {
				found := false
				for _, r := range results {
					if r.Domain == tc.expectedDomain {
						found = true
						// Verify Source Name propagation
						if r.Source != tc.sourceConfig.Name {
							t.Errorf("Expected Source '%s', got '%s'", tc.sourceConfig.Name, r.Source)
						}
						break
					}
				}
				if !found {
					t.Errorf("Expected to find domain '%s' in results", tc.expectedDomain)
				}
			}
		})
	}
}