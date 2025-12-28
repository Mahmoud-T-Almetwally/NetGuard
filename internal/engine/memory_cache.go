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
	t.lock.RLock()
	defer t.lock.RUnlock()

	node := t.root
	
	// Iterate backwards through the input domain
	for i := len(domain) - 1; i >= 0; i-- {
		char := domain[i]

		// --- THE FIX IS HERE ---
		// We are standing on a node. If this node marks the end of a blocked domain
		// (e.g., we just finished matching "google.com"), AND the character we are 
		// about to process is a dot '.', it means the input is a subdomain.
		// Example: Input "ads.google.com"
		// 1. We matched "moc.elgoog". Node is at 'g' (isEnd=true).
		// 2. The loop variable 'char' is now the dot '.' at index 3.
		// 3. Since node.isEnd is true AND char is '.', we return true.
		if node.isEnd && char == '.' {
			return true
		}

		next, exists := node.children[char]
		if !exists {
			// Path ends. 
			// Example: Input "notgoogle.com". 
			// We matched "google.com" (node.isEnd=true).
			// Next char is 't'. It is NOT a dot (so checks above failed).
			// 't' does not exist as a child of the 'g' node.
			// Result: Not blocked.
			return false
		}
		node = next
	}

	// Exact match check
	// This handles the case where input is exactly "google.com".
	// The loop finishes, and we are standing on the last 'g', which isEnd=true.
	return node.isEnd
}

