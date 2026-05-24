package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

func collectCargoPackages() []models.PackageRecord {
	home, _ := os.UserHomeDir()
	var records []models.PackageRecord
	walkForLockfiles(home, "Cargo.lock", func(path string) {
		records = append(records, parseCargoLock(path)...)
	})
	return records
}

func parseCargoLock(path string) []models.PackageRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	dir := filepath.Dir(path)
	var records []models.PackageRecord
	var name, version string

	flush := func() {
		if name != "" {
			records = append(records, models.PackageRecord{
				Name:      name,
				Version:   version,
				Ecosystem: models.EcoCargo,
				Path:      dir,
			})
		}
		name, version = "", ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		} else if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	flush()
	return records
}
