package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

const testFeed = `{
	"generated": "2024-01-01",
	"total_indicators": 3,
	"indicators": [
		{
			"extension_id": "badchromeid001",
			"name": "Evil Chrome Extension",
			"source": "https://security-research.example.com/report-42",
			"insert_date": "2024-01-01",
			"chrome_store_url": "https://chromewebstore.google.com/detail/badchromeid001"
		},
		{
			"extension_id": "monitored002",
			"name": "Store-Monitored Extension",
			"source": "Store Monitoring",
			"insert_date": "2024-02-01",
			"chrome_store_url": ""
		},
		{
			"extension_id": "UPPERCASE003",
			"name": "Case-Test Extension",
			"source": "Store Monitoring",
			"insert_date": "2024-03-01",
			"chrome_store_url": ""
		}
	]
}`

func newTestFeedClient(t *testing.T, handler http.HandlerFunc) *FeedClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewFeedClient(srv.URL, t.TempDir())
}

func TestMalextScan_MatchingChromeExtension(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	exts := []models.ExtensionRecord{
		{ID: "badchromeid001", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ThreatType != models.ThreatMalware {
		t.Errorf("threat type: got %q, want malware", f.ThreatType)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity: got %q, want critical (HTTP URL source → researcher-confirmed)", f.Severity)
	}
	if f.Ecosystem != models.EcoChrome {
		t.Errorf("ecosystem: got %q, want chrome", f.Ecosystem)
	}
	if f.URL != "https://chromewebstore.google.com/detail/badchromeid001" {
		t.Errorf("URL: got %q", f.URL)
	}
}

func TestMalextScan_StoreMonitoringSource_IsHigh(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	exts := []models.ExtensionRecord{
		{ID: "monitored002", Version: "2.0.0", Ecosystem: models.EcoEdge},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity: got %q, want high (non-URL source)", findings[0].Severity)
	}
}

func TestMalextScan_CaseInsensitiveIDMatch(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	// Feed has "UPPERCASE003", querying with lowercase should still match
	exts := []models.ExtensionRecord{
		{ID: "uppercase003", Version: "1.0.0", Ecosystem: models.EcoBrave},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (case-insensitive match), got %d", len(findings))
	}
}

func TestMalextScan_NoMatch(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	exts := []models.ExtensionRecord{
		{ID: "cleanextension999", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unlisted extension, got %d", len(findings))
	}
}

func TestMalextScan_OnlyChromeEcosystems(t *testing.T) {
	called := false
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(testFeed))
	})

	// npm packages and VS Code extensions — feed only covers Chrome/Edge/Brave
	pkgs := []models.PackageRecord{{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm}}
	exts := []models.ExtensionRecord{
		{Publisher: "ms-python", Name: "python", ID: "ms-python.python", Version: "1.0.0", Ecosystem: models.EcoVSCode},
	}

	findings, err := c.Scan(context.Background(), pkgs, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-Chrome inventory, got %d", len(findings))
	}
	if called {
		t.Error("feed should not have been fetched when no Chrome/Edge/Brave extensions are present")
	}
}

// FailOpen: server error should not block the scan — returns nil, nil
func TestMalextScan_FailOpen_ServerError(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	exts := []models.ExtensionRecord{
		{ID: "badchromeid001", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Errorf("expected nil error (fail-open), got: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings (fail-open), got %d", len(findings))
	}
}

func TestMalextScan_FallbackURL_WhenChromeStoreURLEmpty(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	// monitored002 has empty chrome_store_url — should construct fallback
	exts := []models.ExtensionRecord{
		{ID: "monitored002", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	findings, _ := c.Scan(context.Background(), nil, exts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	expected := "https://chromewebstore.google.com/detail/monitored002"
	if findings[0].URL != expected {
		t.Errorf("fallback URL: got %q, want %q", findings[0].URL, expected)
	}
}

func TestMalextScan_CacheHit(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write([]byte(testFeed))
	}))
	defer srv.Close()

	dir := t.TempDir()
	c1 := NewFeedClient(srv.URL, dir)
	c2 := NewFeedClient(srv.URL, dir) // same cache dir

	exts := []models.ExtensionRecord{
		{ID: "badchromeid001", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}

	_, _ = c1.Scan(context.Background(), nil, exts)
	_, _ = c2.Scan(context.Background(), nil, exts)

	// Second scan should use the on-disk cache, not re-fetch
	if fetchCount != 1 {
		t.Errorf("expected 1 feed fetch (second scan should hit cache), got %d", fetchCount)
	}
}

// --- severityFromSource ---

func TestSeverityFromSource(t *testing.T) {
	cases := []struct {
		source string
		want   models.Severity
	}{
		{"https://security-research.example.com/report-42", models.SeverityCritical},
		{"http://blog.example.com/analysis", models.SeverityCritical},
		{"Store Monitoring", models.SeverityHigh},
		{"Manual Review", models.SeverityHigh},
		{"", models.SeverityHigh},
	}
	for _, tc := range cases {
		got := severityFromSource(tc.source)
		if got != tc.want {
			t.Errorf("severityFromSource(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

// --- Debug callback ---

func TestMalextScan_DebugMessages(t *testing.T) {
	c := newTestFeedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testFeed))
	})

	var debugLines []string
	c.SetDebug(func(msg string) { debugLines = append(debugLines, msg) })

	exts := []models.ExtensionRecord{
		{ID: "badchromeid001", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	_, _ = c.Scan(context.Background(), nil, exts)

	if len(debugLines) == 0 {
		t.Error("expected at least one debug line")
	}
}

// --- Cache TTL boundary ---

func TestMalextFeed_CacheTTLExpiry(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write([]byte(testFeed))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cacheFile := dir + "/malext-feed.json"

	// Write the feed to cache, then back-date its mtime to 25 hours ago (past 24h TTL)
	if err := os.WriteFile(cacheFile, []byte(testFeed), 0600); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(cacheFile, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	c := NewFeedClient(srv.URL, dir)
	exts := []models.ExtensionRecord{
		{ID: "badchromeid001", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	_, _ = c.Scan(context.Background(), nil, exts)

	if fetchCount != 1 {
		t.Errorf("expected re-fetch for stale cache (25h old > 24h TTL), fetch count = %d", fetchCount)
	}
}
