package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

const socketBaseURL = "https://api.socket.dev/v0"

// socketIssueTypes maps Socket.dev issue type strings to chainwatch ThreatTypes.
// We only map threat-related types — we explicitly ignore CVE/vulnerability types.
var socketIssueTypes = map[string]models.ThreatType{
	"malware":              models.ThreatMalware,
	"protestware":          models.ThreatProtestware,
	"didYouMean":           models.ThreatTyposquatting,
	"typosquat":            models.ThreatTyposquatting,
	"install":              models.ThreatInstallScript,
	"installScripts":       models.ThreatInstallScript,
	"obfuscatedFiles":      models.ThreatObfuscated,
	"obfuscatedCode":       models.ThreatObfuscated,
	"networkAccess":        models.ThreatNetworkOnInstall,
	"exfiltration":         models.ThreatDataExfil,
	"envVars":              models.ThreatDataExfil,
	"newAuthor":            models.ThreatNewMaintainer,
	"newMaintainer":        models.ThreatNewMaintainer,
	"majorRefactor":        models.ThreatHighChurn,
	"suspiciousString":     models.ThreatSuspicious,
	"highEntropyStrings":   models.ThreatSuspicious,
	"telemetry":            models.ThreatDataExfil,
	"hijackedPackage":      models.ThreatSupplyChain,
	"suspiciouslyPopular":  models.ThreatSuspicious,
}

var socketSeverityMap = map[string]models.Severity{
	"critical": models.SeverityCritical,
	"high":     models.SeverityHigh,
	"middle":   models.SeverityMedium,
	"medium":   models.SeverityMedium,
	"low":      models.SeverityLow,
}

// SocketClient queries Socket.dev for supply chain threats in npm packages.
// API key is optional — unauthenticated requests are rate-limited to ~10/min.
type SocketClient struct {
	apiKey  string
	client  *http.Client
	sem     chan struct{} // concurrency limiter
}

func NewSocketClient(apiKey string) *SocketClient {
	concurrency := 5
	if apiKey != "" {
		concurrency = 20
	}
	return &SocketClient{
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
		sem:     make(chan struct{}, concurrency),
	}
}

func (c *SocketClient) Name() string { return "socket.dev" }

func (c *SocketClient) Scan(
	ctx context.Context,
	pkgs []models.PackageRecord,
	exts []models.ExtensionRecord,
) ([]models.Finding, error) {
	// Socket.dev covers npm packages primarily
	var targets []models.PackageRecord
	for _, p := range pkgs {
		if p.Ecosystem == models.EcoNpm {
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
	)

	for _, pkg := range targets {
		wg.Add(1)
		go func(p models.PackageRecord) {
			defer wg.Done()
			c.sem <- struct{}{}
			defer func() { <-c.sem }()

			findings, err := c.queryPackage(ctx, p)
			if err != nil {
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
	return results, nil
}

type socketIssueResp struct {
	Value struct {
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Title       string `json:"title"`
	} `json:"value"`
}

type socketPackageResp struct {
	Score struct {
		SupplyChainRisk float64 `json:"supplyChainRisk"`
		Malware         float64 `json:"malware"`
	} `json:"score"`
	Alerts []struct {
		Type  string          `json:"type"`
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	} `json:"alerts"`
}

func (c *SocketClient) queryPackage(ctx context.Context, pkg models.PackageRecord) ([]models.Finding, error) {
	// Encode scoped package names: @org/pkg → @org%2Fpkg
	encodedName := url.PathEscape(pkg.Name)
	// Socket.dev uses /npm/{name}/{version} for versioned queries
	endpoint := fmt.Sprintf("%s/npm/%s/%s", socketBaseURL, encodedName, url.PathEscape(pkg.Version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.apiKey+":")))
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		// Back off briefly on rate limit
		time.Sleep(2 * time.Second)
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var data socketPackageResp
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return c.parseAlerts(pkg, data), nil
}

func (c *SocketClient) parseAlerts(pkg models.PackageRecord, data socketPackageResp) []models.Finding {
	var findings []models.Finding

	for _, alert := range data.Alerts {
		alertType := alert.Type
		if alertType == "" {
			alertType = alert.Key
		}

		threatType, ok := socketIssueTypes[alertType]
		if !ok {
			continue // not a threat-relevant issue type — skip
		}

		// Parse the value for description/severity
		var val struct {
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Title       string `json:"title"`
		}
		_ = json.Unmarshal(alert.Value, &val)

		sev := socketSeverityMap[strings.ToLower(val.Severity)]
		if sev == "" {
			sev = models.SeverityMedium
		}

		title := val.Title
		if title == "" {
			title = humanizeThreatType(threatType)
		}

		findings = append(findings, models.Finding{
			Ecosystem:   pkg.Ecosystem,
			Name:        pkg.Name,
			Version:     pkg.Version,
			Source:      "socket.dev",
			ThreatType:  threatType,
			Severity:    sev,
			Title:       title,
			Description: val.Description,
			URL:         fmt.Sprintf("https://socket.dev/npm/package/%s/overview/%s", url.PathEscape(pkg.Name), pkg.Version),
		})
	}
	return findings
}

func humanizeThreatType(t models.ThreatType) string {
	m := map[models.ThreatType]string{
		models.ThreatMalware:          "Confirmed malware",
		models.ThreatSupplyChain:      "Supply chain attack",
		models.ThreatTyposquatting:    "Typosquatting",
		models.ThreatProtestware:      "Protestware",
		models.ThreatInstallScript:    "Executes code on install",
		models.ThreatObfuscated:       "Contains obfuscated code",
		models.ThreatNetworkOnInstall: "Makes network requests on install",
		models.ThreatDataExfil:        "Potential data exfiltration",
		models.ThreatNewMaintainer:    "New or changed maintainer",
		models.ThreatHighChurn:        "Unusually high publish churn",
		models.ThreatSuspicious:       "Suspicious behavior",
	}
	if s, ok := m[t]; ok {
		return s
	}
	return string(t)
}
