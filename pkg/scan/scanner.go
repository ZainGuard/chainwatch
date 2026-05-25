package scan

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

// ThreatIntelClient is the only interface a new threat source needs to implement.
// Add a client, register it in main.go — scanner handles everything else.
type ThreatIntelClient interface {
	Name() string
	Scan(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error)
}

// Debuggable is an optional interface. Clients that implement it receive
// per-request debug lines when --verbose is set. No scanner changes needed
// when adding a new client that supports it.
type Debuggable interface {
	SetDebug(fn func(string))
}

type Scanner struct {
	clients  []ThreatIntelClient
	cache    *Cache
	Progress func(msg string) // optional: progress lines (stderr)
	Debug    func(msg string) // optional: per-request debug lines (stderr)
}

func NewScanner(cacheDir string, clients ...ThreatIntelClient) *Scanner {
	return &Scanner{
		clients: clients,
		cache:   newCache(cacheDir),
	}
}

func (s *Scanner) Run(ctx context.Context, inv *models.Inventory) (*models.ScanResult, error) {
	start := time.Now()

	// Partition packages and extensions into cached vs. uncached per client.
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		allFinds []models.Finding
		runErr   error
	)

	for _, client := range s.clients {
		uncachedPkgs, cachedFinds := s.partitionPackages(client.Name(), inv.Packages)
		uncachedExts, cachedExtFinds := s.partitionExtensions(client.Name(), inv.Extensions)

		allFinds = append(allFinds, cachedFinds...)
		allFinds = append(allFinds, cachedExtFinds...)

		if len(uncachedPkgs) == 0 && len(uncachedExts) == 0 {
			continue
		}

		wg.Add(1)
		go func(c ThreatIntelClient, pkgs []models.PackageRecord, exts []models.ExtensionRecord) {
			defer wg.Done()

			if s.Debug != nil {
				if d, ok := c.(Debuggable); ok {
					d.SetDebug(s.Debug)
				}
			}

			if s.Progress != nil {
				s.Progress(fmt.Sprintf("Querying %s (%d packages, %d extensions)...", c.Name(), len(pkgs), len(exts)))
			}

			findings, err := c.Scan(ctx, pkgs, exts)
			if err != nil {
				mu.Lock()
				runErr = errors.Join(runErr, fmt.Errorf("%s scan failed: %w", c.Name(), err))
				mu.Unlock()
				return
			}

			s.cacheResults(c.Name(), pkgs, findings)
			s.cacheExtResults(c.Name(), exts, findings)

			mu.Lock()
			allFinds = append(allFinds, findings...)
			mu.Unlock()
		}(client, uncachedPkgs, uncachedExts)
	}

	wg.Wait()
	s.cache.save()

	hits, misses := s.cache.stats()
	if s.Progress != nil {
		s.Progress(fmt.Sprintf("Cache: %d hits, %d misses", hits, misses))
	}
	if runErr != nil {
		return nil, runErr
	}

	return &models.ScanResult{
		Inventory:  inv,
		Findings:   dedup(allFinds),
		ScannedAt:  start,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

func (s *Scanner) partitionPackages(source string, pkgs []models.PackageRecord) (uncached []models.PackageRecord, findings []models.Finding) {
	for _, p := range pkgs {
		if f, ok := s.cache.get(source, p.Ecosystem, p.Name, p.Version); ok {
			findings = append(findings, f...)
		} else {
			uncached = append(uncached, p)
		}
	}
	return
}

func (s *Scanner) partitionExtensions(source string, exts []models.ExtensionRecord) (uncached []models.ExtensionRecord, findings []models.Finding) {
	for _, e := range exts {
		// Extensions are keyed by ID as "name", version as version.
		if f, ok := s.cache.get(source, models.Ecosystem(e.Ecosystem), e.ID, e.Version); ok {
			findings = append(findings, f...)
		} else {
			uncached = append(uncached, e)
		}
	}
	return
}

func (s *Scanner) cacheResults(source string, pkgs []models.PackageRecord, findings []models.Finding) {
	byKey := make(map[string][]models.Finding)
	for _, f := range findings {
		k := source + ":" + string(f.Ecosystem) + ":" + f.Name + ":" + f.Version
		byKey[k] = append(byKey[k], f)
	}
	for _, p := range pkgs {
		k := source + ":" + string(p.Ecosystem) + ":" + p.Name + ":" + p.Version
		s.cache.set(source, p.Ecosystem, p.Name, p.Version, byKey[k])
	}
}

func (s *Scanner) cacheExtResults(source string, exts []models.ExtensionRecord, findings []models.Finding) {
	byKey := make(map[string][]models.Finding)
	for _, f := range findings {
		k := source + ":" + string(f.Ecosystem) + ":" + f.Name + ":" + f.Version
		byKey[k] = append(byKey[k], f)
	}
	for _, e := range exts {
		k := source + ":" + string(e.Ecosystem) + ":" + e.ID + ":" + e.Version
		s.cache.set(source, e.Ecosystem, e.ID, e.Version, byKey[k])
	}
}

// dedup removes duplicate findings keyed by source+ecosystem+name+version+threat_type.
func dedup(findings []models.Finding) []models.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		k := f.Source + ":" + string(f.Ecosystem) + ":" + f.Name + ":" + f.Version + ":" + string(f.ThreatType)
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
