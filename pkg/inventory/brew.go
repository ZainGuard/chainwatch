package inventory

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

func collectBrewPackages() []models.PackageRecord {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		return nil
	}
	var records []models.PackageRecord
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		records = append(records, models.PackageRecord{
			Name:      parts[0],
			Version:   parts[len(parts)-1],
			Ecosystem: models.EcoBrew,
		})
	}
	return records
}
