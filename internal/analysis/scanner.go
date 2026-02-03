package analysis

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"netguard/internal/features"
	"netguard/internal/inference"
	"netguard/internal/repository"
	"strings"
	"time"
)

type Scanner struct {
	db        *repository.DomainDB
	predictor *inference.Predictor
	client    *http.Client
}

func NewScanner(db *repository.DomainDB, p *inference.Predictor) *Scanner {
	// Configure a hardened HTTP Client
	tr := &http.Transport{
		// Critical: Malware/Adware sites often have broken/self-signed certs.
		// We want to scan them anyway, not fail.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	return &Scanner{db: db, predictor: p, client: client}
}

// fetchContent tries to download HTML from a URL with browser spoofing
func (s *Scanner) fetchContent(targetUrl string) (string, error) {
	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		return "", err
	}

	// SPOOFING: Look like a real browser to prevent Ad Servers from returning 404/Empty
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Limit reader to avoid memory bombs (e.g. 10MB max)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

// ScanDomain is called asynchronously when a new domain is seen
func (s *Scanner) ScanDomain(domain string, onResult func(string, bool)) {
	// 1. Fetch Content (Try HTTPS, then HTTP)
	targetUrl := "https://" + domain
	htmlContent, err := s.fetchContent(targetUrl)
	
	if err != nil {
		// Fallback to HTTP
		targetUrl = "http://" + domain
		htmlContent, err = s.fetchContent(targetUrl)
		if err != nil {
			log.Printf("[SCAN FAIL] Could not reach %s: %v", domain, err)
			return
		}
	}

	// Log for debugging (remove in production)
	// log.Printf("DEBUG: Domain: %s | HTML Length: %d", domain, len(htmlContent))

	// 2. Extract Features
	feats, err := features.ExtractFeatures(htmlContent, targetUrl, s.predictor.GetFeatureOrder())
	if err != nil {
		log.Printf("Feature extraction failed for %s: %v", domain, err)
		return
	}

	// 3. AI Prediction
	isMal, isAd, err := s.predictor.Predict(feats)
	if err != nil {
		log.Printf("Prediction failed for %s: %v", domain, err)
		return
	}

	if isMal || isAd {
		action := "BLOCK"
		source := "ai_adware"
		if isMal {
			source = "ai_malware"
		}

		log.Printf("🚨 AI DETECTED [%s]: %s", strings.ToUpper(source), domain)

		// Update Database (Persist for next reboot)
		if err := s.db.InsertOrUpdate(domain, action, source); err != nil {
			log.Printf("DB Write Error: %v", err)
		}

		if onResult != nil {
			onResult(domain, true)
		}
	} else {
		// Optional: Mark as "SAFE" in DB so we don't scan it again for a while
		// log.Printf("AI Scanned Safe: %s", domain)
	}
}