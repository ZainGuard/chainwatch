package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

func collectGoModules() []models.PackageRecord {
	home, _ := os.UserHomeDir()
	var records []models.PackageRecord
	seen := make(map[string]bool)
	walkForLockfiles(home, "go.sum", func(path string) {
		for _, r := range parseGoSum(path) {
			key := r.Name + "@" + r.Version + r.Path
			if !seen[key] {
				seen[key] = true
				records = append(records, r)
			}
		}
	})
	return records
}

func parseGoSum(path string) []models.PackageRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	dir := filepath.Dir(path)
	seen := make(map[string]bool)
	var records []models.PackageRecord

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		module := parts[0]
		ver := parts[1]
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		key := module + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		records = append(records, models.PackageRecord{
			Name:      module,
			Version:   ver,
			Ecosystem: models.EcoGo,
			Path:      dir,
		})
	}
	return records
}
