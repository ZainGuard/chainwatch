package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

// DefaultMalExtFeedURL is the community-maintained malicious extension feed.
// Replace with the Zainguard-hosted feed URL when available.
const DefaultMalExtFeedURL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/threat-intel-feeds/malext_feed.json"

const malextFeedTTL = 24 * time.Hour

type malextFeed struct {
	Generated  string        `json:"generated"`
	Total      int           `json:"total_indicators"`
	Indicators []malextEntry `json:"indicators"`
}

type malextEntry struct {
	ExtensionID    string `json:"extension_id"`
	Name           string `json:"name"`
	Source         string `json:"source"`
	InsertDate     string `json:"insert_date"`
	ChromeStoreURL string `json:"chrome_store_url"`
}

// FeedClient checks installed browser extensions against a JSON malicious-extension
// feed (IOC list). A match means confirmed malicious. No match means the extension
// is not in this particular feed — it does NOT mean the extension is safe.
type FeedClient struct {
	feedURL  string
	cacheDir string
	client   *http.Client
	debug    func(msg string)
}

func (c *FeedClient) SetDebug(fn func(string)) { c.debug = fn }

func NewFeedClient(feedURL, cacheDir string) *FeedClient {
	return &FeedClient{
		feedURL:  feedURL,
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *FeedClient) Name() string { return "malext-feed" }

func (c *FeedClient) Scan(
	ctx context.Context,
	pkgs []models.PackageRecord,
	exts []models.ExtensionRecord,
) ([]models.Finding, error) {
	// Feed covers Chrome Web Store IDs — check Chrome, Edge, and Brave extensions
	var targets []models.ExtensionRecord
	for _, e := range exts {
		switch e.Ecosystem {
		case models.EcoChrome, models.EcoEdge, models.EcoBrave:
			if e.ID != "" {
				targets = append(targets, e)
			}
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}

	feed, err := c.loadFeed(ctx)
	if err != nil {
		if c.debug != nil {
			c.debug(fmt.Sprintf("malext-feed  ERR  %v", err))
		}
		// Fail-open: a feed fetch failure should not block the rest of the scan
		return nil, nil
	}

	lookup := make(map[string]malextEntry, len(feed.Indicators))
	for _, e := range feed.Indicators {
		lookup[strings.ToLower(e.ExtensionID)] = e
	}

	if c.debug != nil {
		c.debug(fmt.Sprintf("malext-feed  %d indicators loaded, checking %d extensions", len(lookup), len(targets)))
	}

	var findings []models.Finding
	for _, ext := range targets {
		entry, ok := lookup[strings.ToLower(ext.ID)]
		if !ok {
			continue
		}

		storeURL := entry.ChromeStoreURL
		if storeURL == "" {
			storeURL = "https://chromewebstore.google.com/detail/" + ext.ID
		}

		findings = append(findings, models.Finding{
			Ecosystem:   ext.Ecosystem,
			Name:        ext.ID,
			Version:     ext.Version,
			Source:      c.Name(),
			ThreatType:  models.ThreatMalware,
			Severity:    severityFromSource(entry.Source),
			Title:       fmt.Sprintf("Confirmed malicious: %s", entry.Name),
			Description: fmt.Sprintf("Flagged %s. Attribution: %s", entry.InsertDate, entry.Source),
			URL:         storeURL,
		})
	}

	if c.debug != nil && len(findings) > 0 {
		c.debug(fmt.Sprintf("malext-feed  %d match(es) against known-malicious list", len(findings)))
	}
	return findings, nil
}

// severityFromSource returns Critical when the finding is backed by a named
// threat report (researcher-confirmed), High for generic store monitoring.
// This does not imply extensions absent from the feed are safe.
func severityFromSource(source string) models.Severity {
	if strings.HasPrefix(source, "http") {
		return models.SeverityCritical
	}
	return models.SeverityHigh
}

func (c *FeedClient) loadFeed(ctx context.Context) (*malextFeed, error) {
	cachePath := filepath.Join(c.cacheDir, "malext-feed.json")

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < malextFeedTTL {
			data, err := os.ReadFile(cachePath)
			if err == nil {
				var feed malextFeed
				if json.Unmarshal(data, &feed) == nil {
					if c.debug != nil {
						c.debug(fmt.Sprintf("malext-feed  cache hit (fetched %s)", info.ModTime().Format("2006-01-02 15:04")))
					}
					return &feed, nil
				}
			}
		}
	}

	if c.debug != nil {
		c.debug("malext-feed  fetching feed")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.feedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	var feed malextFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	_ = os.WriteFile(cachePath, data, 0600) // best-effort cache write
	return &feed, nil
}
