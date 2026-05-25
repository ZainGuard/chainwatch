package output

import (
	"strings"
	"testing"

	"github.com/zainguard/chainwatch/pkg/models"
)

// --- mergeByComponent ---

func TestMergeByComponent_Empty(t *testing.T) {
	merged := mergeByComponent(nil)
	if len(merged) != 0 {
		t.Errorf("expected 0 merged findings, got %d", len(merged))
	}
}

func TestMergeByComponent_SingleFinding(t *testing.T) {
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "evil-pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Credential stealer"},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if len(merged[0].Sources) != 1 || merged[0].Sources[0] != "socket.dev" {
		t.Errorf("sources: got %v", merged[0].Sources)
	}
}

func TestMergeByComponent_TwoSources_SameComponent(t *testing.T) {
	findings := []models.Finding{
		{Ecosystem: models.EcoChrome, Name: "badextid001", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Malware"},
		{Ecosystem: models.EcoChrome, Name: "badextid001", Version: "1.0.0", Source: "malext-feed", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Malware confirmed by feed"},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged row (same component), got %d", len(merged))
	}
	m := merged[0]
	if len(m.Sources) != 2 {
		t.Errorf("expected 2 sources, got %v", m.Sources)
	}
	// Both sources present
	sourceSet := make(map[string]bool)
	for _, s := range m.Sources {
		sourceSet[s] = true
	}
	if !sourceSet["socket.dev"] || !sourceSet["malext-feed"] {
		t.Errorf("expected both socket.dev and malext-feed in sources: %v", m.Sources)
	}
}

func TestMergeByComponent_BestDescription_LongerWins(t *testing.T) {
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "source-a", ThreatType: models.ThreatObfuscated, Description: "Short"},
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "source-b", ThreatType: models.ThreatObfuscated, Description: "Much longer and more informative description"},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if merged[0].Description != "Much longer and more informative description" {
		t.Errorf("description: got %q (expected longer one to win)", merged[0].Description)
	}
}

func TestMergeByComponent_DifferentThreatTypes_NotMerged(t *testing.T) {
	// Same component but different threat types → separate rows
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatDataExfil},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 2 {
		t.Errorf("expected 2 merged findings (different threat types), got %d", len(merged))
	}
}

func TestMergeByComponent_DifferentVersions_NotMerged(t *testing.T) {
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "2.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 2 {
		t.Errorf("expected 2 merged findings (different versions), got %d", len(merged))
	}
}

func TestMergeByComponent_DeduplicatesSources(t *testing.T) {
	// Same source appearing twice for the same component should only appear once
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
		{Ecosystem: models.EcoNpm, Name: "pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
	}
	merged := mergeByComponent(findings)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if len(merged[0].Sources) != 1 {
		t.Errorf("expected deduplicated sources (1), got %v", merged[0].Sources)
	}
}

func TestMergeByComponent_PreservesInsertionOrder(t *testing.T) {
	findings := []models.Finding{
		{Ecosystem: models.EcoNpm, Name: "aaa", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
		{Ecosystem: models.EcoNpm, Name: "bbb", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
		{Ecosystem: models.EcoNpm, Name: "ccc", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware},
	}
	merged := mergeByComponent(findings)
	names := []string{merged[0].Name, merged[1].Name, merged[2].Name}
	if names[0] != "aaa" || names[1] != "bbb" || names[2] != "ccc" {
		t.Errorf("insertion order not preserved: got %v", names)
	}
}

// --- filterBySeverity ---

func TestFilterBySeverity_AtThreshold(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityMedium},
		{Severity: models.SeverityLow},
	}
	got := filterBySeverity(findings, models.SeverityMedium)
	if len(got) != 3 { // critical, high, medium — not low
		t.Errorf("filter medium+: expected 3 findings, got %d", len(got))
	}
}

func TestFilterBySeverity_CriticalOnly(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityLow},
	}
	got := filterBySeverity(findings, models.SeverityCritical)
	if len(got) != 1 {
		t.Errorf("filter critical: expected 1 finding, got %d", len(got))
	}
}

func TestFilterBySeverity_AllPass(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityLow},
	}
	got := filterBySeverity(findings, models.SeverityLow)
	if len(got) != 2 {
		t.Errorf("filter low+: expected 2 findings, got %d", len(got))
	}
}

// --- PrintTable output ---

func TestPrintTable_NoFindings(t *testing.T) {
	SetNoColor(true)
	var buf strings.Builder
	result := &models.ScanResult{
		Inventory: &models.Inventory{
			Packages:   []models.PackageRecord{{Name: "lodash", Ecosystem: models.EcoNpm}},
			Extensions: []models.ExtensionRecord{{ID: "ext1", Ecosystem: models.EcoChrome}},
		},
	}
	PrintTable(&buf, result, models.SeverityLow)
	out := buf.String()
	if !strings.Contains(out, "No threats detected") {
		t.Errorf("expected 'No threats detected', got: %q", out)
	}
	if !strings.Contains(out, "1 packages") {
		t.Errorf("expected package count in output, got: %q", out)
	}
}

func TestPrintTable_ShowsFindings(t *testing.T) {
	SetNoColor(true)
	var buf strings.Builder
	result := &models.ScanResult{
		Inventory: &models.Inventory{},
		Findings: []models.Finding{
			{Ecosystem: models.EcoNpm, Name: "evil-pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Credential stealer"},
		},
	}
	PrintTable(&buf, result, models.SeverityLow)
	out := buf.String()
	if !strings.Contains(out, "evil-pkg") {
		t.Errorf("expected package name in output, got: %q", out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL label in output, got: %q", out)
	}
	if !strings.Contains(out, "socket.dev") {
		t.Errorf("expected source attribution in output, got: %q", out)
	}
}

func TestPrintTable_MultiSourceAttribution(t *testing.T) {
	SetNoColor(true)
	var buf strings.Builder
	result := &models.ScanResult{
		Inventory: &models.Inventory{},
		Findings: []models.Finding{
			// Both sources report the same extension — same ecosystem+name+version+threat_type
			{Ecosystem: models.EcoChrome, Name: "badext", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Malicious extension"},
			{Ecosystem: models.EcoChrome, Name: "badext", Version: "1.0.0", Source: "malext-feed", ThreatType: models.ThreatMalware, Severity: models.SeverityCritical, Description: "Confirmed IOC match"},
		},
	}
	PrintTable(&buf, result, models.SeverityLow)
	out := buf.String()
	// Should show bracket notation for multiple sources in the attribution line
	if !strings.Contains(out, "[socket.dev, malext-feed]") && !strings.Contains(out, "[malext-feed, socket.dev]") {
		t.Errorf("expected multi-source bracket notation, got: %q", out)
	}
	// Should count as 1 unique component, not 2
	if strings.Contains(out, "2 threats") {
		t.Errorf("multi-source same component should count as 1 threat, not 2; got: %q", out)
	}
	if !strings.Contains(out, "1 threat") {
		t.Errorf("expected '1 threat' in summary, got: %q", out)
	}
}

func TestPrintTable_FiltersOutBelowMinSeverity(t *testing.T) {
	SetNoColor(true)
	var buf strings.Builder
	result := &models.ScanResult{
		Inventory: &models.Inventory{},
		Findings: []models.Finding{
			{Ecosystem: models.EcoNpm, Name: "noisy-pkg", Version: "1.0.0", Source: "socket.dev", ThreatType: models.ThreatSuspicious, Severity: models.SeverityLow},
		},
	}
	PrintTable(&buf, result, models.SeverityMedium)
	out := buf.String()
	if !strings.Contains(out, "No threats detected") {
		t.Errorf("expected low-severity finding to be filtered out at medium threshold, got: %q", out)
	}
}
