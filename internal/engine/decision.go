package engine

import (
	"errors"
	"log"
	"netguard/internal/repository"
)

type Engine struct {
	domainTrie* DomainTrie
}

func (e* Engine) Init(domainDB* repository.DomainDB) error {
	domains, err := domainDB.GetAll()
	if err != nil{
		log.Printf("Loading Domains from DB failed: %v", err)
		return err
	}

	e.domainTrie = NewDomainTrie()

	e.domainTrie.BulkInsert(domains)

	return nil
}

func (e* Engine) Decision(domain string) (bool, error) {
	if e.domainTrie == nil {
		return false, errors.New("Engine Uninitialized")
	}

	if e.domainTrie.ShouldBlock(domain) {
		return true, nil
	}

	return false, nil
}