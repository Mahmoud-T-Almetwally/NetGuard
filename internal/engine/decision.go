package engine

import (
	"errors"
	"log"
	"netguard/internal/analysis"
	"netguard/internal/repository"
	"sync"
)

type Engine struct {
	domainTrie   *DomainTrie
	scanner      *analysis.Scanner
	pendingScans sync.Map
}

func (e *Engine) Init(domainDB *repository.DomainDB, scanner *analysis.Scanner) error {
	domains, err := domainDB.GetBlocklist()
	if err != nil {
		log.Printf("Loading Domains from DB failed: %v", err)
		return err
	}

	e.scanner = scanner

	e.domainTrie = NewDomainTrie()

	e.domainTrie.BulkInsert(domains)

	return nil
}

func (e *Engine) AddRule(domain string) {
	e.domainTrie.Insert(domain)
}

func (e *Engine) Decision(domain string) (bool, error) {
	if e.domainTrie == nil {
		return false, errors.New("engine uninitialized")
	}

	// 1. Check RAM (Fast Path)
	if e.domainTrie.ShouldBlock(domain) {
		return true, nil
	}

	// 2. If unknown, trigger Background Scan (Slow Path)
	// Check if we are already scanning this domain to avoid packet flooding
	if _, loading := e.pendingScans.LoadOrStore(domain, true); !loading {

		// Run scan in background
		go func(d string) {
			// Ensure we remove from pending map when done
			defer e.pendingScans.Delete(d)

			// Call Scanner
			e.scanner.ScanDomain(d, func(scannedDomain string, shouldBlock bool) {
				if shouldBlock {
					e.AddRule(scannedDomain) // Update RAM
				}
			})
		}(domain)
	}

	// Default: Allow packet while scanning (Optimistic approach)
	// If it's malware, we block the NEXT packet or stream.
	return false, nil
}
