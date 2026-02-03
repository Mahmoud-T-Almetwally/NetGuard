package inference

import (
	"math/rand"
	"netguard/internal/features"
	"os"
	"testing"
)

const modelPath = "../../data/models"

func TestMain(m *testing.M) {
	// Setup
	if err := InitONNX(); err != nil {
		println("Skipping ONNX tests: Lib not found or Init failed:", err.Error())
		os.Exit(1)
	}

	// Run Tests
	code := m.Run()

	// Teardown
	CleanupONNX()
	
	os.Exit(code)
}

func TestPredictor_LifecycleAndLogic(t *testing.T) {
	// Check if models exist
	if _, err := os.Stat(modelPath + "/malware_classifier.onnx"); os.IsNotExist(err) {
		t.Skip("Skipping test: Model files not found in " + modelPath)
	}

	// 1. Init
	p, err := NewPredictor(modelPath)
	if err != nil {
		t.Fatalf("Failed to create predictor: %v", err)
	}
	defer p.Close()

	// 2. Check Feature Loading
	if len(p.GetFeatureOrder()) == 0 {
		t.Error("Feature order is empty")
	}

	// 3. Run Inference (Logic)
	// We create a fake input vector of random 0.0-1.0 floats
	numFeatures := len(p.GetFeatureOrder())
	fakeFeatures := make([]float32, numFeatures)
	for i := 0; i < numFeatures; i++ {
		fakeFeatures[i] = rand.Float32()
	}

	isMal, isAd, err := p.Predict(fakeFeatures)
	if err != nil {
		t.Fatalf("Prediction failed: %v", err)
	}

	// We can't assert True/False correctness without labelled data,
	// but we assert that it didn't crash and returned bools.
	t.Logf("Random Input Result -> Malware: %v, Adware: %v", isMal, isAd)
}

func TestPredictor_DimensionMismatch(t *testing.T) {
	if _, err := os.Stat(modelPath + "/malware_classifier.onnx"); os.IsNotExist(err) {
		t.Skip("Models missing")
	}

	p, _ := NewPredictor(modelPath)
	defer p.Close()

	// Pass vector with wrong size (e.g., only 1 feature)
	// The ONNX runtime SHOULD return an error
	_, _, err := p.Predict([]float32{0.5})
	if err == nil {
		t.Error("Expected error for dimension mismatch, got nil")
	} else {
		t.Logf("Correctly caught mismatch error: %v", err)
	}
}

// Benchmark: Run with `go test -bench=. ./internal/inference`
func BenchmarkPredict(b *testing.B) {
	if _, err := os.Stat(modelPath + "/malware_classifier.onnx"); os.IsNotExist(err) {
		b.Skip("Models missing")
	}

	p, _ := NewPredictor(modelPath)
	defer p.Close()

	numFeatures := len(p.GetFeatureOrder())
	fakeFeatures := make([]float32, numFeatures)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Predict(fakeFeatures)
	}
}

func TestModelLogic_Synthetic(t *testing.T) {
	// 1. Setup
	if _, err := os.Stat(modelPath + "/malware_classifier.onnx"); os.IsNotExist(err) {
		t.Skip("Models not found")
	}

	pred, err := NewPredictor(modelPath)
	if err != nil {
		t.Fatalf("Failed to load predictor: %v", err)
	}
	defer pred.Close()

	// 2. Create Synthetic "Adware/Malware" HTML
	// We stuff this with keywords and structures that SHOULD trigger the model.
	badHTML := `
	<html>
	<head><title>Winner! Casino Bonus</title></head>
	<body>
		<script>
			eval(unescape("bad_code"));
			document.write("tracking");
			window.location = "http://malware.com";
		</script>
		<script src="ads.js"></script>
		<script src="tracker.js"></script>
		<script src="miner.js"></script>
		<iframe src="popup.html"></iframe>
		<iframe src="ad.html"></iframe>
		
		<h1>CONGRATULATIONS! YOU WON A BITCOIN PRIZE!</h1>
		<p>Click here to verify your account and claim your crypto wallet.</p>
		<p>Spin the wheel! Gambling Casino Bet Jackpot!</p>
		<a href="http://badsite.com/download.exe">Download Now</a>
	</body>
	</html>
	`
	
	// 3. Extract Features
	// We use a fake URL that looks suspicious too
	targetURL := "http://suspicious-casino-win.com/login.php"
	
	feats, err := features.ExtractFeatures(badHTML, targetURL, pred.GetFeatureOrder())
	if err != nil {
		t.Fatalf("Feature extraction failed: %v", err)
	}

	// --- DEBUG: Print the Feature Vector ---
	// This allows you to see exactly what the model sees.
	t.Logf("\n--- Feature Vector Dump ---")
	for i, val := range feats {
		name := pred.GetFeatureOrder()[i]
		// Only log non-zero features to reduce noise
		if val > 0 {
			t.Logf("[%s]: %f", name, val)
		}
	}
	t.Logf("---------------------------\n")

	// 4. Run Prediction
	isMal, isAd, err := pred.Predict(feats)
	if err != nil {
		t.Fatalf("Prediction failed: %v", err)
	}

	t.Logf("Prediction Result -> Malware: %v | Adware: %v", isMal, isAd)

	// 5. Assertion
	if !isMal && !isAd {
		t.Error("FAILURE: The model allowed a highly suspicious synthetic page.")
		t.Error("Possible causes: Feature mapping mismatch or model was trained on very different data.")
	} else {
		t.Log("SUCCESS: The model correctly blocked the synthetic content.")
	}
}

// TestFeatureMapping ensures the feature names in txt match the extraction logic
func TestFeatureMapping(t *testing.T) {
	pred, _ := NewPredictor(modelPath)
	defer pred.Close()

	order := pred.GetFeatureOrder()
	
	// Basic check to ensure we have the expected count
	// (Assuming you trained on ~27 features)
	if len(order) < 20 {
		t.Errorf("Warning: Only found %d features. Expected > 20.", len(order))
	}
	
	// Check for critical features
	critical := []string{"num_script_tags", "kw_adware", "is_https", "domain_len"}
	for _, c := range critical {
		found := false
		for _, f := range order {
			if f == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Critical feature missing from feature_names.txt: %s", c)
		}
	}
}