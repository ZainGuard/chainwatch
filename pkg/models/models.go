package models

import "time"

// Ecosystem identifies where a package or extension came from.
type Ecosystem string

const (
	EcoVSCode    Ecosystem = "vscode"
	EcoCursor    Ecosystem = "cursor"
	EcoWindsurf  Ecosystem = "windsurf"
	EcoZed       Ecosystem = "zed"
	EcoJetBrains Ecosystem = "jetbrains"
	EcoChrome    Ecosystem = "chrome"
	EcoEdge      Ecosystem = "edge"
	EcoBrave     Ecosystem = "brave"
	EcoFirefox   Ecosystem = "firefox"
	EcoNpm       Ecosystem = "npm"
	EcoPip       Ecosystem = "pip"
	EcoCargo     Ecosystem = "cargo"
	EcoGo        Ecosystem = "go"
	EcoGem       Ecosystem = "gem"
	EcoBrew      Ecosystem = "brew"
	EcoMCP       Ecosystem = "mcp"
)

// ThreatType describes the nature of a detected supply chain threat.
// chainwatch detects malicious intent — NOT CVEs or vulnerabilities.
type ThreatType string

const (
	ThreatMalware          ThreatType = "malware"
	ThreatSupplyChain      ThreatType = "supply-chain-attack"
	ThreatTyposquatting    ThreatType = "typosquatting"
	ThreatProtestware      ThreatType = "protestware"
	ThreatInstallScript    ThreatType = "install-script"
	ThreatObfuscated       ThreatType = "obfuscated-code"
	ThreatNetworkOnInstall ThreatType = "network-on-install"
	ThreatDataExfil        ThreatType = "data-exfiltration"
	ThreatNewMaintainer    ThreatType = "new-maintainer"
	ThreatHighChurn        ThreatType = "high-churn"
	ThreatMaliciousExt     ThreatType = "malicious-extension"
	ThreatSuspicious       ThreatType = "suspicious"
)

// Severity of a detected threat.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityRank returns a numeric rank for comparison (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// ExtensionRecord describes a single installed IDE or browser extension.
type ExtensionRecord struct {
	ID        string    `json:"id"`
	Version   string    `json:"version"`
	Name      string    `json:"name,omitempty"`
	Publisher string    `json:"publisher,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Profile   string    `json:"profile,omitempty"` // browser profile (e.g. "Default", "Profile 3")
}

// PackageRecord describes a single installed package.
type PackageRecord struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Path      string    `json:"path,omitempty"`
}

// Inventory is the full supply chain snapshot for one machine.
type Inventory struct {
	Extensions  []ExtensionRecord `json:"extensions"`
	Packages    []PackageRecord   `json:"packages"`
	CollectedAt time.Time         `json:"collectedAt"`
}

// Finding is a detected supply chain threat.
// It is explicitly NOT a CVE — it represents malicious intent or behavior.
type Finding struct {
	Ecosystem   Ecosystem  `json:"ecosystem"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Source      string     `json:"source"`
	ThreatType  ThreatType `json:"threat_type"`
	Severity    Severity   `json:"severity"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	URL         string     `json:"url,omitempty"`
}

// ScanResult is the complete output of a chainwatch scan.
type ScanResult struct {
	Inventory  *Inventory `json:"inventory"`
	Findings   []Finding  `json:"findings"`
	ScannedAt  time.Time  `json:"scanned_at"`
	DurationMs int64      `json:"duration_ms"`
	// Warnings contains non-fatal errors from threat intel sources (rate limits,
	// outages, auth failures). A non-empty Warnings list means some packages may
	// not have been checked — CI gates should treat this as a degraded scan.
	Warnings []string `json:"warnings,omitempty"`
}

// Summary counts findings by severity.
func (r *ScanResult) Summary() map[Severity]int {
	m := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
	}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}
