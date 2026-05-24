package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

const (
	cacheTTL     = 6 * time.Hour
	cacheMaxSize = 10_000
)

type cacheEntry struct {
	Findings  []models.Finding `json:"findings"`
	FetchedAt time.Time        `json:"fetchedAt"`
}

// Cache stores threat intel results locally so repeat scans don't hit the
// APIs for the same package@version. TTL is 6 hours — threats can emerge
// quickly, so we don't cache longer than that.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	path    string
	hits    int
	misses  int
}

func newCache(cacheDir string) *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
		path:    filepath.Join(cacheDir, "threat-cache.json"),
	}
	c.load()
	return c
}

func cacheKey(source, ecosystem, name, version string) string {
	return source + ":" + string(ecosystem) + ":" + name + ":" + version
}

func (c *Cache) get(source string, eco models.Ecosystem, name, version string) ([]models.Finding, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cacheKey(source, string(eco), name, version)]
	if !ok || time.Since(e.FetchedAt) > cacheTTL {
		c.misses++
		return nil, false
	}
	c.hits++
	return e.Findings, true
}

func (c *Cache) set(source string, eco models.Ecosystem, name, version string, findings []models.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= cacheMaxSize {
		c.evictOldest()
	}
	c.entries[cacheKey(source, string(eco), name, version)] = cacheEntry{
		Findings:  findings,
		FetchedAt: time.Now(),
	}
}

func (c *Cache) stats() (hits, misses int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

func (c *Cache) save() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.Marshal(c.entries)
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}

func (c *Cache) load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var entries map[string]cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	now := time.Now()
	for k, e := range entries {
		if now.Sub(e.FetchedAt) <= cacheTTL {
			c.entries[k] = e
		}
	}
}

func (c *Cache) evictOldest() {
	var oldest string
	var oldestTime time.Time
	for k, e := range c.entries {
		if oldest == "" || e.FetchedAt.Before(oldestTime) {
			oldest = k
			oldestTime = e.FetchedAt
		}
	}
	if oldest != "" {
		delete(c.entries, oldest)
	}
}
