package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

const (
	socketBaseURL   = "https://api.socket.dev/v0"
	socketBatchSize = 500 // max PURLs per request (API limit is 1024)
)

// socketIssueTypes maps Socket.dev alert type strings to chainwatch ThreatTypes.
// Only supplyChainRisk category alerts are mapped — vulnerability/CVE types are
// excluded at the category level before this map is consulted.
var socketIssueTypes = map[string]models.ThreatType{
	// Confirmed malicious
	"malware":         models.ThreatMalware,
	"protestware":     models.ThreatProtestware,
	"hijackedPackage": models.ThreatSupplyChain,

	// Typosquatting
	"didYouMean": models.ThreatTyposquatting,
	"typosquat":  models.ThreatTyposquatting,

	// Install-time execution
	"install":        models.ThreatInstallScript,
	"installScripts": models.ThreatInstallScript,
	"shellAccess":    models.ThreatInstallScript,

	// Obfuscation / suspicious code
	"obfuscatedFiles":    models.ThreatObfuscated,
	"obfuscatedCode":     models.ThreatObfuscated,
	"highEntropyStrings": models.ThreatObfuscated,
	"usesEval":           models.ThreatObfuscated,
	"gptAnomaly":         models.ThreatSuspicious,
	"suspiciousString":   models.ThreatSuspicious,
	"urlStrings":         models.ThreatSuspicious,
	"dynamicRequire":     models.ThreatSuspicious,

	// Network / data exfiltration
	"networkAccess":       models.ThreatNetworkOnInstall,
	"exfiltration":        models.ThreatDataExfil,
	"envVars":             models.ThreatDataExfil,
	"telemetry":           models.ThreatDataExfil,
	"filesystemAccess":    models.ThreatSuspicious,

	// Maintainer signals
	"newAuthor":           models.ThreatNewMaintainer,
	"newMaintainer":       models.ThreatNewMaintainer,
	"majorRefactor":       models.ThreatHighChurn,
	"suspiciouslyPopular": models.ThreatSuspicious,

	// Chrome extension-specific
	"chromePermission": models.ThreatSuspicious,
	"extensionMalware": models.ThreatMalware,
}

var socketSeverityMap = map[string]models.Severity{
	"critical": models.SeverityCritical,
	"high":     models.SeverityHigh,
	"middle":   models.SeverityMedium,
	"medium":   models.SeverityMedium,
	"low":      models.SeverityLow,
}

// SocketClient queries Socket.dev for supply chain threats in npm packages.
type SocketClient struct {
	apiKey string
	client *http.Client
	debug  func(msg string)
}

func (c *SocketClient) SetDebug(fn func(string)) { c.debug = fn }

func NewSocketClient(apiKey string) *SocketClient {
	return &SocketClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *SocketClient) Name() string { return "socket.dev" }

func (c *SocketClient) Scan(
	ctx context.Context,
	pkgs []models.PackageRecord,
	exts []models.ExtensionRecord,
) ([]models.Finding, error) {
	var npmPkgs []models.PackageRecord
	for _, p := range pkgs {
		if p.Ecosystem == models.EcoNpm {
			npmPkgs = append(npmPkgs, p)
		}
	}

	// VS Code-compatible and Chrome-based extensions
	var scanExts []models.ExtensionRecord
	for _, e := range exts {
		switch e.Ecosystem {
		case models.EcoVSCode, models.EcoCursor, models.EcoWindsurf, models.EcoZed:
			if e.Publisher != "" && e.Name != "" {
				scanExts = append(scanExts, e)
			}
		case models.EcoChrome, models.EcoEdge, models.EcoBrave:
			if e.ID != "" {
				scanExts = append(scanExts, e)
			}
		}
	}

	if len(npmPkgs) == 0 && len(scanExts) == 0 {
		return nil, nil
	}

	var allFindings []models.Finding

	for i := 0; i < len(npmPkgs); i += socketBatchSize {
		end := i + socketBatchSize
		if end > len(npmPkgs) {
			end = len(npmPkgs)
		}
		findings, err := c.queryBatch(ctx, npmPkgs[i:end], nil)
		if err != nil {
			return allFindings, err
		}
		allFindings = append(allFindings, findings...)
	}

	for i := 0; i < len(scanExts); i += socketBatchSize {
		end := i + socketBatchSize
		if end > len(scanExts) {
			end = len(scanExts)
		}
		findings, err := c.queryBatch(ctx, nil, scanExts[i:end])
		if err != nil {
			return allFindings, err
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

type socketPurlReq struct {
	Components []socketComponent `json:"components"`
}

type socketComponent struct {
	PURL string `json:"purl"`
}

type socketPurlResult struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Type    string        `json:"type"`
	Alerts  []socketAlert `json:"alerts"`
}

type socketAlert struct {
	Type     string          `json:"type"`
	Severity string          `json:"severity"`
	Category string          `json:"category"`
	Props    json.RawMessage `json:"props"`
}

type socketAlertProps struct {
	Notes       string `json:"notes"`
	Note        string `json:"note"` // Chrome extensions use "note" (singular)
	Description string `json:"description"`
	Title       string `json:"title"`
	Risk        string `json:"risk"`
}

func (c *SocketClient) queryBatch(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error) {
	components := make([]socketComponent, 0, len(pkgs)+len(exts))
	pkgIndex := make(map[string]models.PackageRecord, len(pkgs))
	extIndex := make(map[string]models.ExtensionRecord, len(exts)*3)

	for _, p := range pkgs {
		purl := fmt.Sprintf("pkg:npm/%s@%s", url.PathEscape(p.Name), p.Version)
		components = append(components, socketComponent{PURL: purl})
		pkgIndex[p.Name+"@"+p.Version] = p
	}

	chromeIndex := make(map[string]models.ExtensionRecord, len(exts))

	for _, e := range exts {
		switch e.Ecosystem {
		case models.EcoChrome, models.EcoEdge, models.EcoBrave:
			// Chrome PURL has no version — Socket resolves it from the store
			purl := fmt.Sprintf("pkg:chrome/%s", e.ID)
			components = append(components, socketComponent{PURL: purl})
			chromeIndex[e.ID] = e
		default:
			// VS Code-compatible: pkg:vscode/<publisher>/<name>@<version>
			purl := fmt.Sprintf("pkg:vscode/%s/%s@%s",
				url.PathEscape(e.Publisher), url.PathEscape(e.Name), e.Version)
			components = append(components, socketComponent{PURL: purl})
			// Index by multiple key formats — Socket may return bare name, publisher.name, or publisher/name
			extIndex[strings.ToLower(e.Name)+"@"+e.Version] = e
			extIndex[strings.ToLower(e.Publisher+"."+e.Name)+"@"+e.Version] = e
			extIndex[strings.ToLower(e.Publisher+"/"+e.Name)+"@"+e.Version] = e
		}
	}

	body, _ := json.Marshal(socketPurlReq{Components: components})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		socketBaseURL+"/purl?alerts=true",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	total := len(pkgs) + len(exts)
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		if c.debug != nil {
			c.debug(fmt.Sprintf("socket.dev  ERR  batch(%d)  %v", total, err))
		}
		return nil, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()
	if c.debug != nil {
		c.debug(fmt.Sprintf("socket.dev  %d  batch(%d)  %dms", resp.StatusCode, total, elapsed))
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("socket.dev: auth failed (HTTP %d) — check CHAINWATCH_SOCKET_KEY", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if c.debug != nil {
			c.debug("socket.dev  429  rate limited")
		}
		return nil, fmt.Errorf("socket.dev: rate limited (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("socket.dev: unexpected status %d", resp.StatusCode)
	}

	// Response is NDJSON — one JSON object per line
	limited := io.LimitReader(resp.Body, 50<<20) // 50MB cap
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 1<<20), 4<<20) // 4MB per line

	var findings []models.Finding
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var result socketPurlResult
		if err := json.Unmarshal(line, &result); err != nil {
			continue
		}

		switch result.Type {
		case "chrome":
			ext, ok := chromeIndex[result.Name]
			if ok {
				findings = append(findings, c.parseExtAlerts(ext, result)...)
			}
		case "vscode":
			ext, ok := extIndex[strings.ToLower(result.Name)+"@"+result.Version]
			if !ok {
				for k, e := range extIndex {
					if strings.HasPrefix(k, strings.ToLower(result.Name)+"@") {
						ext = e
						ok = true
						break
					}
				}
			}
			if ok {
				findings = append(findings, c.parseExtAlerts(ext, result)...)
			}
		default: // "npm" or empty
			pkg, ok := pkgIndex[result.Name+"@"+result.Version]
			if !ok {
				for k, p := range pkgIndex {
					if strings.HasPrefix(k, result.Name+"@") {
						pkg = p
						ok = true
						break
					}
				}
			}
			if ok {
				findings = append(findings, c.parseAlerts(pkg, result)...)
			}
		}
	}

	if c.debug != nil && len(findings) > 0 {
		c.debug(fmt.Sprintf("socket.dev  %d finding(s) in batch", len(findings)))
	}
	return findings, scanner.Err()
}

func (c *SocketClient) parseExtAlerts(ext models.ExtensionRecord, result socketPurlResult) []models.Finding {
	var findings []models.Finding

	for _, alert := range result.Alerts {
		if alert.Category == "vulnerability" || alert.Category == "license" {
			continue
		}
		threatType, ok := socketIssueTypes[alert.Type]
		if !ok {
			continue
		}
		sev := socketSeverityMap[strings.ToLower(alert.Severity)]
		if sev == "" {
			sev = models.SeverityLow
		}
		var props socketAlertProps
		if len(alert.Props) > 0 {
			_ = json.Unmarshal(alert.Props, &props)
		}
		description := props.Notes
		if description == "" {
			description = props.Note // Chrome uses "note" (singular)
		}
		if description == "" {
			description = props.Description
		}
		title := props.Title
		if title == "" {
			title = humanizeThreatType(threatType)
		}

		var socketURL string
		switch ext.Ecosystem {
		case models.EcoChrome, models.EcoEdge, models.EcoBrave:
			socketURL = fmt.Sprintf("https://socket.dev/chrome/package/%s/overview/%s",
				ext.ID, result.Version)
		default:
			socketURL = fmt.Sprintf("https://socket.dev/vscode/package/%s/%s/overview/%s",
				url.PathEscape(ext.Publisher), url.PathEscape(ext.Name), ext.Version)
		}

		version := ext.Version
		if version == "" || version == "unknown" {
			version = result.Version // use Socket's resolved version for Chrome
		}

		findings = append(findings, models.Finding{
			Ecosystem:   ext.Ecosystem,
			Name:        ext.ID,
			Version:     version,
			Source:      "socket.dev",
			ThreatType:  threatType,
			Severity:    sev,
			Title:       title,
			Description: description,
			URL:         socketURL,
		})
	}
	return findings
}

func (c *SocketClient) parseAlerts(pkg models.PackageRecord, result socketPurlResult) []models.Finding {
	var findings []models.Finding

	for _, alert := range result.Alerts {
		// Skip CVEs and license issues — chainwatch is not a vulnerability scanner
		if alert.Category == "vulnerability" || alert.Category == "license" {
			continue
		}

		threatType, ok := socketIssueTypes[alert.Type]
		if !ok {
			continue
		}

		sev := socketSeverityMap[strings.ToLower(alert.Severity)]
		if sev == "" {
			sev = models.SeverityLow
		}

		var props socketAlertProps
		if len(alert.Props) > 0 {
			_ = json.Unmarshal(alert.Props, &props)
		}
		description := props.Notes
		if description == "" {
			description = props.Note
		}
		if description == "" {
			description = props.Description
		}
		title := props.Title
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
			Description: description,
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
