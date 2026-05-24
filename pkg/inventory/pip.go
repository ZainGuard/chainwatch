package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

func collectPipPackages() []models.PackageRecord {
	var records []models.PackageRecord
	for _, dir := range pipSitePackageDirs() {
		records = append(records, scanSitePackages(dir)...)
	}
	return records
}

func pipSitePackageDirs() []string {
	home, _ := os.UserHomeDir()
	var dirs []string

	switch runtime.GOOS {
	case "darwin":
		if entries, err := os.ReadDir(filepath.Join(home, "Library/Python")); err == nil {
			for _, e := range entries {
				dirs = append(dirs,
					filepath.Join(home, "Library/Python", e.Name(), "lib/python/site-packages"))
			}
		}
		for _, base := range []string{"/usr/local/lib", "/opt/homebrew/lib"} {
			if entries, err := os.ReadDir(base); err == nil {
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), "python3") {
						dirs = append(dirs, filepath.Join(base, e.Name(), "site-packages"))
					}
				}
			}
		}
	case "linux":
		localLib := filepath.Join(home, ".local/lib")
		if entries, err := os.ReadDir(localLib); err == nil {
			for _, e := range entries {
				dirs = append(dirs, filepath.Join(localLib, e.Name(), "site-packages"))
			}
		}
		dirs = append(dirs, "/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages")
	}

	for _, root := range commonProjectRoots(home) {
		appendVenvSitePackages(root, &dirs)
	}
	return dirs
}

func commonProjectRoots(home string) []string {
	candidates := []string{"Projects", "projects", "code", "dev", "src", "work"}
	var roots []string
	for _, c := range candidates {
		p := filepath.Join(home, c)
		if _, err := os.Stat(p); err == nil {
			roots = append(roots, p)
		}
	}
	return roots
}

func appendVenvSitePackages(root string, dirs *[]string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, venvName := range []string{"venv", ".venv", "env"} {
			libDir := filepath.Join(root, e.Name(), venvName, "lib")
			if pyDirs, err := os.ReadDir(libDir); err == nil {
				for _, pd := range pyDirs {
					*dirs = append(*dirs, filepath.Join(libDir, pd.Name(), "site-packages"))
				}
			}
		}
	}
}

func scanSitePackages(dir string) []models.PackageRecord {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []models.PackageRecord
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}
		if rec := parsePipMetadata(filepath.Join(dir, e.Name(), "METADATA"), dir); rec != nil {
			records = append(records, *rec)
		}
	}
	return records
}

func parsePipMetadata(path, installDir string) *models.PackageRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name: "):
			name = strings.TrimPrefix(line, "Name: ")
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		}
		if name != "" && version != "" {
			break
		}
	}
	if name == "" {
		return nil
	}
	return &models.PackageRecord{
		Name:      name,
		Version:   version,
		Ecosystem: models.EcoPip,
		Path:      installDir,
	}
}
