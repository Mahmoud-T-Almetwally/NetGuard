package engine

import (
	"sync"
)


type TrieNode struct {
	children map[byte]*TrieNode
	isEnd    bool
}

type DomainTrie struct {
	root *TrieNode
	lock sync.RWMutex
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &TrieNode{
			children: make(map[byte]*TrieNode),
		},
	}
}

// We insert in REVERSE order: "bad.com" -> 'm', 'o', 'c', '.', 'd', 'a', 'b'
func (t *DomainTrie) Insert(domain string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	node := t.root
	// Iterate backwards through the string
	for i := len(domain) - 1; i >= 0; i-- {
		char := domain[i]
		
		if node.children[char] == nil {
			node.children[char] = &TrieNode{
				children: make(map[byte]*TrieNode),
			}
		}
		node = node.children[char]
	}
	node.isEnd = true
}

// BulkInsert is optimized for loading the initial database
// It only locks the mutex ONCE for the whole batch, saving massive CPU time.
func (t *DomainTrie) BulkInsert(domains []string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, domain := range domains {
		node := t.root
		for i := len(domain) - 1; i >= 0; i-- {
			char := domain[i]
			if node.children[char] == nil {
				node.children[char] = &TrieNode{
					children: make(map[byte]*TrieNode),
				}
			}
			node = node.children[char]
		}
		node.isEnd = true
	}
}

// ShouldBlock checks if a domain (or its parent) is blocked.
// Returns true if blocked.
func (t *DomainTrie) ShouldBlock(domain string) bool {
	t.lock.RLock() // Read Lock: Multiple threads can read at the same time
	defer t.lock.RUnlock()

	node := t.root
	
	// Iterate backwards
	for i := len(domain) - 1; i >= 0; i-- {
		char := domain[i]

		// 1. Check if the current node marks a blocked parent domain
		// This handles the wildcard logic. 
		// Example: We blocked "google.com". Input is "ads.google.com".
		// We traversed "moc.elgoog". node.isEnd is True here.
		// We must ensure the next char is a dot '.' or we are at the end, 
		// otherwise we might accidentally block "google.com.ph" (if we only blocked google.com) 
		// or "notgoogle.com".
		if node.isEnd {
			// If we hit an 'end' node, and the character we just processed was a dot,
			// or if we are at the very start of the traversal, it's a subdomain match.
			// However, in reverse traversal, simple isEnd checks are usually sufficient 
			// if we enforce explicit structure.
			
			// A simpler check for "subdomain or exact match":
			// If we are at "google.com" (reversed), and the previous char read was '.'
			// then it is a match.
			if i+1 < len(domain) && domain[i+1] == '.' {
				return true
			}
		}

		next, exists := node.children[char]
		if !exists {
			return false
		}
		node = next
	}

	// Exact match check (e.g. input was exactly "google.com")
	return node.isEnd
}

