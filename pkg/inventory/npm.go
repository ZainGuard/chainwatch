package inventory

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

func collectNPMPackages() []models.PackageRecord {
	var records []models.PackageRecord

	if out, err := exec.Command("npm", "list", "-g", "--json", "--depth=0").Output(); err == nil {
		records = append(records, parseNPMListJSON(out)...)
	}

	home, _ := os.UserHomeDir()
	walkForLockfiles(home, "package-lock.json", func(path string) {
		records = append(records, parsePackageLock(path)...)
	})

	return records
}

type npmListOut struct {
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parseNPMListJSON(data []byte) []models.PackageRecord {
	var out npmListOut
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	records := make([]models.PackageRecord, 0, len(out.Dependencies))
	for name, dep := range out.Dependencies {
		records = append(records, models.PackageRecord{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: models.EcoNpm,
			Path:      "global",
		})
	}
	return records
}

type packageLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parsePackageLock(path string) []models.PackageRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	dir := filepath.Dir(path)
	var records []models.PackageRecord

	for key, pkg := range lock.Packages {
		if !strings.HasPrefix(key, "node_modules/") {
			continue
		}
		records = append(records, models.PackageRecord{
			Name:      strings.TrimPrefix(key, "node_modules/"),
			Version:   pkg.Version,
			Ecosystem: models.EcoNpm,
			Path:      dir,
		})
	}
	if len(records) == 0 {
		for name, dep := range lock.Dependencies {
			records = append(records, models.PackageRecord{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: models.EcoNpm,
				Path:      dir,
			})
		}
	}
	return records
}
