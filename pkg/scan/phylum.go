package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

const phylumBaseURL = "https://api.phylum.io/api/v0"

// phylumEcosystems maps chainwatch ecosystem names to Phylum package type strings.
// Only ecosystems that Phylum covers and that are threat-relevant are included.
var phylumEcosystems = map[models.Ecosystem]string{
	models.EcoPip:   "pypi",
	models.EcoCargo: "cargo",
	models.EcoGo:    "golang",
	models.EcoGem:   "rubygems",
	// npm is handled by Socket.dev; we still include it here as fallback
	models.EcoNpm: "npm",
}

// phylumDomains are the Phylum issue domains we care about.
// We explicitly exclude "vulnerability" (CVEs) and "license".
var threatDomains = map[string]bool{
	"malicious_code": true,
	"author":         true,
	"supply_chain":   true,
	"engineering":    false, // code quality, not threats
	"vulnerability":  false, // CVEs — explicitly excluded
	"license":        false,
}

var phylumSeverityMap = map[string]models.Severity{
	"critical": models.SeverityCritical,
	"high":     models.SeverityHigh,
	"medium":   models.SeverityMedium,
	"low":      models.SeverityLow,
	"info":     models.SeverityLow,
}

// PhylumClient queries Phylum.io for supply chain threats.
// An API key is required (free tier available at phylum.io).
type PhylumClient struct {
	apiKey string
	client *http.Client
	sem    chan struct{}
	debug  func(msg string)
}

func (c *PhylumClient) SetDebug(fn func(string)) { c.debug = fn }

func NewPhylumClient(apiKey string) *PhylumClient {
	return &PhylumClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 20 * time.Second},
		sem:    make(chan struct{}, 10),
	}
}

func (c *PhylumClient) Name() string { return "phylum.io" }

func (c *PhylumClient) Scan(
	ctx context.Context,
	pkgs []models.PackageRecord,
	exts []models.ExtensionRecord,
) ([]models.Finding, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	var targets []models.PackageRecord
	for _, p := range pkgs {
		if _, ok := phylumEcosystems[p.Ecosystem]; ok {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []models.Finding
		errs    []error
	)

	for _, pkg := range targets {
		wg.Add(1)
		go func(p models.PackageRecord) {
			defer wg.Done()
			c.sem <- struct{}{}
			defer func() { <-c.sem }()

			findings, err := c.queryPackage(ctx, p)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			if len(findings) > 0 {
				mu.Lock()
				results = append(results, findings...)
				mu.Unlock()
			}
		}(pkg)
	}
	wg.Wait()

	if len(errs) > 0 {
		return results, fmt.Errorf("phylum.io: %d package lookup(s) failed (first: %w)", len(errs), errs[0])
	}
	return results, nil
}

type phylumBatchReq struct {
	Packages []phylumPkgRef `json:"packages"`
}

type phylumPkgRef struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
}

type phylumIssue struct {
	Tag         string  `json:"tag"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Domain      string  `json:"domain"`
	Score       float64 `json:"score"`
}

type phylumPackageResult struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Type    string        `json:"type"`
	Issues  []phylumIssue `json:"issues"`
}

func (c *PhylumClient) queryPackage(ctx context.Context, pkg models.PackageRecord) ([]models.Finding, error) {
	ecoType, ok := phylumEcosystems[pkg.Ecosystem]
	if !ok {
		return nil, nil
	}

	reqBody, _ := json.Marshal(phylumBatchReq{
		Packages: []phylumPkgRef{{
			Name:    pkg.Name,
			Version: pkg.Version,
			Type:    ecoType,
		}},
	})

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		phylumBaseURL+"/data/packages/batch",
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnprocessableEntity {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("phylum: status %d for %s@%s", resp.StatusCode, pkg.Name, pkg.Version)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var results []phylumPackageResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	var findings []models.Finding
	for _, result := range results {
		for _, issue := range result.Issues {
			if !threatDomains[issue.Domain] {
				continue // skip CVEs, license issues, engineering quality
			}
			sev := phylumSeverityMap[issue.Severity]
			if sev == "" {
				sev = models.SeverityMedium
			}
			findings = append(findings, models.Finding{
				Ecosystem:   pkg.Ecosystem,
				Name:        pkg.Name,
				Version:     pkg.Version,
				Source:      "phylum.io",
				ThreatType:  phylumDomainToThreat(issue.Domain, issue.Tag),
				Severity:    sev,
				Title:       issue.Title,
				Description: issue.Description,
				URL:         fmt.Sprintf("https://app.phylum.io/packages/%s/%s/%s", ecoType, pkg.Name, pkg.Version),
			})
		}
	}
	return findings, nil
}

func phylumDomainToThreat(domain, tag string) models.ThreatType {
	switch domain {
	case "malicious_code":
		return models.ThreatMalware
	case "author", "supply_chain":
		return models.ThreatSupplyChain
	}
	return models.ThreatSuspicious
}
