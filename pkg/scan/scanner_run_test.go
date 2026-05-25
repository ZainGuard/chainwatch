package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/zainguard/chainwatch/pkg/models"
)

type partialErrClient struct{}

func (c *partialErrClient) Name() string { return "socket.dev" }

func (c *partialErrClient) Scan(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error) {
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

func TestScannerRun_PreservesPartialFindingsOnClientError(t *testing.T) {
	s := NewScanner(t.TempDir(), &partialErrClient{})
	inv := &models.Inventory{Packages: []models.PackageRecord{{
		Ecosystem: models.EcoNpm,
		Name:      "lodash",
		Version:   "4.17.21",
	}}}

	result, err := s.Run(context.Background(), inv)
	if err == nil {
		t.Fatal("expected scanner error, got nil")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 partial finding, got %d", len(result.Findings))
	}
}
