package lsvid

import (
	"sync"
	"time"
)

// JtiCache tracks seen JTI values to prevent replay attacks.
type JtiCache struct {
	mu      sync.Mutex
	entries map[string]int64 // jti → expiresAt unix timestamp
}

// NewJtiCache creates a new JtiCache.
func NewJtiCache() *JtiCache {
	return &JtiCache{
		entries: make(map[string]int64),
	}
}

// SeenOrRecord returns true if the JTI has already been seen.
// If not seen, it records the JTI with its expiration time.
// Expired entries are automatically evicted on each call.
func (c *JtiCache) SeenOrRecord(jti string, expiresAt int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries
	now := time.Now().Unix()
	for k, exp := range c.entries {
		if exp <= now {
			delete(c.entries, k)
		}
	}

	// Check if already seen
	if _, exists := c.entries[jti]; exists {
		return true
	}

	// Record
	c.entries[jti] = expiresAt
	return false
}
