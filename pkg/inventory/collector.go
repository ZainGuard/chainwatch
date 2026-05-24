package inventory

import (
	"os"
	"time"

	"github.com/zainguard/chainwatch/pkg/models"
)

// Collect performs a full supply chain inventory scan across all supported
// IDEs, browsers, and package managers on the current machine.
func Collect() *models.Inventory {
	inv := &models.Inventory{CollectedAt: time.Now().UTC()}

	inv.Extensions = append(inv.Extensions, collectIDEExtensions()...)
	inv.Extensions = append(inv.Extensions, collectBrowserExtensions()...)
	inv.Extensions = append(inv.Extensions, collectJetBrainsPlugins()...)

	inv.Packages = append(inv.Packages, collectNPMPackages()...)
	inv.Packages = append(inv.Packages, collectPipPackages()...)
	inv.Packages = append(inv.Packages, collectCargoPackages()...)
	inv.Packages = append(inv.Packages, collectGoModules()...)
	inv.Packages = append(inv.Packages, collectBrewPackages()...)

	return inv
}

// walkForLockfiles recursively searches root for files named filename,
// calling fn for each one found. Skips .git, node_modules, and vendor dirs.
func walkForLockfiles(root, filename string, fn func(path string)) {
	const maxDepth = 6
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".cache" {
				continue
			}
			path := dir + "/" + name
			if e.IsDir() {
				walk(path, depth+1)
			} else if name == filename {
				fn(path)
			}
		}
	}
	walk(root, 0)
}
