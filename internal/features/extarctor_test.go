package features

import (
	"strings"
	"testing"
)

// Mock HTML content that triggers specific features
const mockMalwareHTML = `
<html>
<head>
    <title>Urgent Update Required</title>
    <meta name="description" content="security">
</head>
<body>
    <h1>Verify your account</h1>
    <script>
        var x = "test";
        eval("malicious_code");
        unescape("%20");
    </script>
    <script src="bad.js"></script>
    <iframe src="hidden.html" width="0"></iframe>
    <form action="steal.php">
        <input type="text" name="user">
        <input type="password" name="pass">
        <input type="hidden" name="token">
    </form>
    <p>Bitcoin crypto wallet mining</p>
    <a href="http://external.com">Link</a>
</body>
</html>
`

func TestExtractFeatures_Logic(t *testing.T) {
	// Define a custom order for testing to verify mapping logic works
	// independent of the full model file
	featureOrder := []string{
		"num_script_tags",
		"count_eval",
		"count_unescape",
		"num_iframes",
		"num_password_inputs",
		"kw_crypto",
		"is_https",
		"domain_len",
	}

	targetURL := "https://example.com/login"

	features, err := ExtractFeatures(mockMalwareHTML, targetURL, featureOrder)
	if err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}

	// Define expected values based on mockMalwareHTML
	expected := map[string]float32{
		"num_script_tags":     2.0, // Inline + External
		"count_eval":          1.0,
		"count_unescape":      1.0,
		"num_iframes":         1.0,
		"num_password_inputs": 1.0,
		"kw_crypto":           4.0, // "Bitcoin", "crypto" (wallet/mining are separate kws)
		"is_https":            1.0, // URL is https
		"domain_len":          11.0, // "example.com"
	}

	for i, name := range featureOrder {
		got := features[i]
		want := expected[name]

		if got != want {
			t.Errorf("Feature '%s': got %f, want %f", name, got, want)
		}
	}
}

func TestExtractFeatures_FaultTolerance(t *testing.T) {
	featureOrder := []string{"html_len"}

	// 1. Empty HTML
	vec, err := ExtractFeatures("", "http://test.com", featureOrder)
	if err != nil {
		t.Errorf("Should not fail on empty HTML: %v", err)
	}
	if len(vec) == 0 || vec[0] != 0 {
		t.Error("Empty HTML should return length 0")
	}

	// 2. Bad URL
	_, err = ExtractFeatures("<html></html>", "::not-a-url::", featureOrder)
	if err != nil {
		// It might not error, but it shouldn't panic. 
		// url.Parse usually handles garbage gracefully by returning empty structs
	}
}

// Benchmark: Run this with `go test -bench=. ./internal/features`
func BenchmarkExtractFeatures(b *testing.B) {
	// A reasonably complex feature set
	featureOrder := []string{
		"html_len", "text_len", "num_script_tags", "count_eval", 
		"kw_malware", "kw_adware", "is_https", "path_len",
	}
	
	// Repeat the HTML to make it "heavy" (~10KB)
	heavyHTML := strings.Repeat(mockMalwareHTML, 20)
	url := "https://benchmark.com/test"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractFeatures(heavyHTML, url, featureOrder)
	}
}