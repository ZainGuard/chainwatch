package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zainguard/chainwatch/pkg/models"
)

type partialErrClient struct{}

func (c *partialErrClient) Name() string { return "socket.dev" }

func (c *partialErrClient) Scan(_ context.Context, _ []models.PackageRecord, _ []models.ExtensionRecord) ([]models.Finding, error) {
	return []models.Finding{{
		Ecosystem:  models.EcoNpm,
		Name:       "lodash",
		Version:    "4.17.21",
		Source:     "socket.dev",
		ThreatType: models.ThreatMalware,
		Severity:   models.SeverityCritical,
		Title:      "malware",
	}}, errors.New("later batch failed")
}

// When a client returns (partial findings, error), Run should:
// - preserve the partial findings in the result
// - record a warning instead of returning a fatal error
// - not cache the partial results (so the packages are re-queried next run)
func TestScannerRun_PreservesPartialFindingsOnClientError(t *testing.T) {
	s := NewScanner(t.TempDir(), &partialErrClient{})
	inv := &models.Inventory{Packages: []models.PackageRecord{{
		Ecosystem: models.EcoNpm,
		Name:      "lodash",
		Version:   "4.17.21",
	}}}

	result, err := s.Run(context.Background(), inv)
	if err != nil {
		t.Fatalf("Run should not return a fatal error on client failure, got: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 partial finding, got %d", len(result.Findings))
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(result.Warnings), result.Warnings)
	}
	if !strings.Contains(result.Warnings[0], "socket.dev") {
		t.Errorf("expected warning to name the failing source, got: %q", result.Warnings[0])
	}
}
