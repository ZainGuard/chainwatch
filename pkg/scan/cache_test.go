package scan

import (
	"testing"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

func TestCacheKey_Format(t *testing.T) {
	got := cacheKey("socket.dev", "npm", "lodash", "4.17.21")
	want := "socket.dev:npm:lodash:4.17.21"
	if got != want {
		t.Errorf("cacheKey: got %q, want %q", got, want)
	}
}

func TestCache_SetAndGet_Hit(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	findings := []models.Finding{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm, Source: "socket.dev", ThreatType: models.ThreatObfuscated, Severity: models.SeverityHigh},
	}
	c.set("socket.dev", models.EcoNpm, "lodash", "4.17.21", findings)

	got, ok := c.get("socket.dev", models.EcoNpm, "lodash", "4.17.21")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if len(got) != 1 || got[0].Name != "lodash" {
		t.Errorf("unexpected findings: %+v", got)
	}
}

func TestCache_Miss_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	_, ok := c.get("socket.dev", models.EcoNpm, "nonexistent", "1.0.0")
	if ok {
		t.Error("expected cache miss for unknown key")
	}
}

func TestCache_TTL_Expiry(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	// Directly inject an expired entry
	k := cacheKey("socket.dev", "npm", "old-pkg", "1.0.0")
	c.entries[k] = cacheEntry{
		Findings:  []models.Finding{{Name: "old-pkg"}},
		FetchedAt: time.Now().Add(-7 * time.Hour), // 7h > 6h TTL
	}

	_, ok := c.get("socket.dev", models.EcoNpm, "old-pkg", "1.0.0")
	if ok {
		t.Error("expected cache miss for expired entry (7h old, TTL=6h)")
	}
}

func TestCache_TTL_WithinBoundary(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	// Entry just within TTL (5h 59m)
	k := cacheKey("socket.dev", "npm", "recent-pkg", "2.0.0")
	c.entries[k] = cacheEntry{
		Findings:  []models.Finding{{Name: "recent-pkg"}},
		FetchedAt: time.Now().Add(-5*time.Hour - 59*time.Minute),
	}

	_, ok := c.get("socket.dev", models.EcoNpm, "recent-pkg", "2.0.0")
	if !ok {
		t.Error("expected cache hit for entry within TTL (5h59m < 6h)")
	}
}

func TestCache_Stats(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	c.set("socket.dev", models.EcoNpm, "a", "1.0.0", nil)
	c.get("socket.dev", models.EcoNpm, "a", "1.0.0") // hit
	c.get("socket.dev", models.EcoNpm, "b", "1.0.0") // miss

	hits, misses := c.stats()
	if hits != 1 {
		t.Errorf("hits: got %d, want 1", hits)
	}
	if misses != 1 {
		t.Errorf("misses: got %d, want 1", misses)
	}
}

func TestCache_Eviction_MaxSize(t *testing.T) {
	dir := t.TempDir()
	c := newCache(dir)

	// Fill cache to max
	for i := 0; i < cacheMaxSize; i++ {
		name := "pkg-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i/26))
		c.set("socket.dev", models.EcoNpm, name, "1.0.0", nil)
	}

	if len(c.entries) != cacheMaxSize {
		t.Fatalf("expected %d entries before overflow, got %d", cacheMaxSize, len(c.entries))
	}

	// Adding one more should evict the oldest
	c.set("socket.dev", models.EcoNpm, "overflow-pkg", "1.0.0", nil)

	if len(c.entries) != cacheMaxSize {
		t.Errorf("expected %d entries after eviction, got %d", cacheMaxSize, len(c.entries))
	}
}

func TestCache_EmptyFindings_Cached(t *testing.T) {
	// A package with no threats should be cached as empty (not treated as a miss)
	dir := t.TempDir()
	c := newCache(dir)

	c.set("socket.dev", models.EcoNpm, "clean-pkg", "1.0.0", []models.Finding{})

	findings, ok := c.get("socket.dev", models.EcoNpm, "clean-pkg", "1.0.0")
	if !ok {
		t.Error("expected cache hit for clean package (empty findings)")
	}
	if len(findings) != 0 {
		t.Errorf("expected empty findings, got %d", len(findings))
	}
}

func TestCache_Persistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Write to cache then reload from disk
	c1 := newCache(dir)
	c1.set("phylum.io", models.EcoPip, "requests", "2.28.0", []models.Finding{
		{Name: "requests", Source: "phylum.io", Severity: models.SeverityMedium},
	})
	c1.save()

	c2 := newCache(dir)
	findings, ok := c2.get("phylum.io", models.EcoPip, "requests", "2.28.0")
	if !ok {
		t.Fatal("expected cache hit after reload from disk")
	}
	if len(findings) != 1 || findings[0].Name != "requests" {
		t.Errorf("unexpected findings after reload: %+v", findings)
	}
}
