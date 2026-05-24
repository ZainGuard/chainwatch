package output

import (
	"encoding/json"
	"io"

	"github.com/zainguard/chainwatch/pkg/models"
)

type jsonSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type jsonOutput struct {
	ScannedAt  string           `json:"scanned_at"`
	DurationMs int64            `json:"duration_ms"`
	Summary    jsonSummary      `json:"summary"`
	Findings   []models.Finding `json:"findings"`
}

// PrintJSON writes a JSON scan result to out.
// The output intentionally has no cves/cvss fields — chainwatch detects threats, not CVEs.
func PrintJSON(out io.Writer, result *models.ScanResult, minSev models.Severity) error {
	filtered := filterBySeverity(result.Findings, minSev)
	counts := countBySeverity(filtered)

	payload := jsonOutput{
		ScannedAt:  result.ScannedAt.UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs: result.DurationMs,
		Summary: jsonSummary{
			Critical: counts[models.SeverityCritical],
			High:     counts[models.SeverityHigh],
			Medium:   counts[models.SeverityMedium],
			Low:      counts[models.SeverityLow],
		},
		Findings: filtered,
	}
	if payload.Findings == nil {
		payload.Findings = []models.Finding{}
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
