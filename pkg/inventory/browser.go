package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/zainguard/chainwatch/pkg/models"
)

type browserDef struct {
	eco  models.Ecosystem
	dirs []string
}

func browserExtensionDirs() []browserDef {
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "darwin":
		return []browserDef{
			{
				eco: models.EcoChrome,
				dirs: []string{
					filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
					filepath.Join(home, "Library/Application Support/Google/Chrome/Profile 1/Extensions"),
				},
			},
			{
				eco: models.EcoEdge,
				dirs: []string{
					filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/Extensions"),
				},
			},
			{
				eco: models.EcoBrave,
				dirs: []string{
					filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
				},
			},
		}
	case "linux":
		return []browserDef{
			{
				eco: models.EcoChrome,
				dirs: []string{
					filepath.Join(home, ".config/google-chrome/Default/Extensions"),
					filepath.Join(home, ".config/chromium/Default/Extensions"),
				},
			},
			{
				eco: models.EcoEdge,
				dirs: []string{
					filepath.Join(home, ".config/microsoft-edge/Default/Extensions"),
				},
			},
			{
				eco: models.EcoBrave,
				dirs: []string{
					filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/Extensions"),
				},
			},
		}
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		return []browserDef{
			{eco: models.EcoChrome, dirs: []string{filepath.Join(local, "Google/Chrome/User Data/Default/Extensions")}},
			{eco: models.EcoEdge, dirs: []string{filepath.Join(local, "Microsoft/Edge/User Data/Default/Extensions")}},
			{eco: models.EcoBrave, dirs: []string{filepath.Join(local, "BraveSoftware/Brave-Browser/User Data/Default/Extensions")}},
		}
	}
	return nil
}

func collectBrowserExtensions() []models.ExtensionRecord {
	var records []models.ExtensionRecord
	for _, def := range browserExtensionDirs() {
		for _, dir := range def.dirs {
			records = append(records, scanChromiumExtensions(dir, def.eco)...)
		}
	}
	return records
}

type chromeManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func scanChromiumExtensions(dir string, eco models.Ecosystem) []models.ExtensionRecord {
	extDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []models.ExtensionRecord
	for _, extDir := range extDirs {
		if !extDir.IsDir() {
			continue
		}
		rec := parseBrowserExtensionDir(filepath.Join(dir, extDir.Name()), eco)
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records
}

func parseBrowserExtensionDir(extIDDir string, eco models.Ecosystem) *models.ExtensionRecord {
	extID := filepath.Base(extIDDir)
	versionDirs, err := os.ReadDir(extIDDir)
	if err != nil {
		return nil
	}
	for _, vDir := range versionDirs {
		if !vDir.IsDir() {
			continue
		}
		rec := parseChromeManifest(
			filepath.Join(extIDDir, vDir.Name(), "manifest.json"),
			extID,
			eco,
		)
		if rec != nil {
			return rec
		}
	}
	return nil
}

func parseChromeManifest(path, extID string, eco models.Ecosystem) *models.ExtensionRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m chromeManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &models.ExtensionRecord{
		ID:        extID,
		Version:   m.Version,
		Name:      m.Name,
		Ecosystem: eco,
	}
}
