package analysis

import (
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"netguard/internal/inference"
	"netguard/internal/repository"
)

// Define the path to your models relative to this test file
const modelPath = "../../data/models"

func TestRealWorld_ScanDomain(t *testing.T) {
	// 1. Skip in "Short" mode (Standard CI/CD) because this hits real networks
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 2. Setup Dependencies
	// A. ONNX Environment
	if err := inference.InitONNX(); err != nil {
		t.Fatalf("ONNX Init failed: %v", err)
	}
	defer inference.CleanupONNX()

	// B. Database (In-Memory for speed, but fully functional)
	db := &repository.DomainDB{}
	if err := db.InitDB(":memory:"); err != nil {
		t.Fatalf("DB Init failed: %v", err)
	}

	// C. Predictor
	// Check if models exist first
	if _, err := os.Stat(modelPath + "/adware_classifier.onnx"); os.IsNotExist(err) {
		t.Fatalf("Models not found at %s. Please train python models first.", modelPath)
	}
	pred, err := inference.NewPredictor(modelPath)
	if err != nil {
		t.Fatalf("Predictor Init failed: %v", err)
	}
	defer pred.Close()

	// D. Scanner
	scanner := NewScanner(db, pred)

	// 3. The Test Data (StevenBlack Adware Subset)
	// Note: We included a known "Benign" site (example.com) as a control.
	targets := []string{
		"example.com",               // Control: Should be ALLOW
		"graph.accountkit.com",      // Ad/Tracker
		"ad-assets.futurecdn.net",
		"ck.getcookiestxt.com",
		"eu1.clevertap-prod.com",
		"wizhumpgyros.com",
		"coccyxwickimp.com",
		"webmail-who-int.000webhostapp.com",
		"010sec.com",
		"01mspmd5yalky8.com",
		"0byv9mgbn0.com",
		"ns6.0pendns.org",
		"dns.0pengl.com",
		"12724.xyz",
		"21736.xyz",
		"www.analytics.247sports.com",
		"2no.co",
		"www.2no.co",
		"logitechlogitechglobal.112.2o7.net",
		"www.logitechlogitechglobal.112.2o7.net",
		"2s11.com",
		"30-day-change.com",
		"www.30-day-change.com",
		"mclean.f.360.cn",
		"mvconf.f.360.cn",
		"care.help.360.cn",
		"eul.s.360.cn",
		"g.s.360.cn",
		"p.s.360.cn",
		"aicleaner.shouji.360.cn",
		"ssl.360antivirus.org",
		"ad.360in.com",
		"mclean.lato.cloud.360safe.com",
		"mvconf.lato.cloud.360safe.com",
		"mclean.cloud.360safe.com",
		"mvconf.cloud.360safe.com",
		"mclean.uk.cloud.360safe.com",
		"mvconf.uk.cloud.360safe.com",
		"3lift.org",
		"448ff4fcfcd199a.com",
		"44chan.me",
		"4ourkidsky.com",
		"5kv261gjmq04c9.com",
		"88chan.pw",
		"new.915yzt.cn",
		"tempinfo.96.lt",
		"abdurantom.com",
		"abtasty.net",
		"analytics.modul.ac.at",
		"acalvet.com",
		"acbras.com",
		"graph.accountkit.com",
		"www.graph.accountkit.com",
		"go.ad1data.com",
		"metrics.adage.com",
		"adaptivecss.org",
		"ads30.adcolony.com",
		"androidads23.adcolony.com",
		"events3.adcolony.com",
		"events3alt.adcolony.com",
		"sdk.adincube.com",
		"app.adjust.com",
		"cdn.admitad-connect.com",
		"macro.adnami.io",
		"acdn.adnxs.com",
		"prebid.adnxs.com",
		"www.prebid.adnxs.com",
		"sstats.adobe.com",
		"adorebeauty.org",
		"feedback.adrecover.com",
	}

	// 4. Run the Test Loop
	t.Logf("Starting Real-World Scan on %d domains...", len(targets))
	t.Log("---------------------------------------------------")

	for _, domain := range targets {
		start := time.Now()

		// --- EXECUTE SCAN ---
		// We can't easily check return values since ScanDomain is async/void in your design,
		// but for this test, we assume ScanDomain is called synchronously here.
		// If your ScanDomain runs in a `go func`, this test needs a WaitGroup or channel.
		// Assuming for this test logic that ScanDomain blocks until finished:
		
		// To test properly, we need to modify ScanDomain slightly to be synchronous 
		// OR we rely on the DB side-effect.
		scanner.ScanDomain(domain, nil)
		
		duration := time.Since(start)

		// --- VERIFY RESULTS ---
		// Check if it got into the DB
		rule, err := db.GetRule(domain)

		if err != nil {
			log.Printf("DB Returned with: %v", err)
		}
		
		status := "IGNORED (Network Fail/Empty)"
		if err == nil && rule != nil {
			status = rule.Action + " (" + rule.Source + ")"
		} else {
            // Check if the domain is actually reachable
            if isReachable(domain) {
                status = "BENIGN (AI decided safe)"
            }
        }

		t.Logf("[%s] %s | Time: %v | Result: %s", 
            checkReachabilityIcon(domain), 
            domain, 
            duration.Round(time.Millisecond), 
            status,
        )
	}
	t.Log("---------------------------------------------------")
}

// Helper to visually check if network is the issue
func checkReachabilityIcon(domain string) string {
    client := http.Client{Timeout: 2 * time.Second}
    _, err := client.Get("http://" + domain)
    if err != nil {
        return "❌" // Domain is dead/unreachable
    }
    return "✅" // Domain is alive
}

func isReachable(domain string) bool {
    client := http.Client{Timeout: 2 * time.Second}
    _, err := client.Get("http://" + domain)
    return err == nil
}