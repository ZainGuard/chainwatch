package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

var ideExtensionDirs = map[models.Ecosystem][]string{
	models.EcoVSCode:   {".vscode/extensions"},
	models.EcoCursor:   {".cursor/extensions"},
	models.EcoWindsurf: {".windsurf/extensions"},
	models.EcoZed:      {".zed/extensions"},
}

func collectIDEExtensions() []models.ExtensionRecord {
	home, _ := os.UserHomeDir()
	var records []models.ExtensionRecord

	for eco, relPaths := range ideExtensionDirs {
		for _, rel := range relPaths {
			dir := filepath.Join(home, rel)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if rec := parseIDEExtension(filepath.Join(dir, e.Name()), eco); rec != nil {
					records = append(records, *rec)
				}
			}
		}
	}
	return records
}

type vscodePkg struct {
	Publisher string `json:"publisher"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

func parseIDEExtension(dir string, eco models.Ecosystem) *models.ExtensionRecord {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg vscodePkg
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Name == "" {
		return nil
	}
	id := strings.ToLower(pkg.Publisher + "." + pkg.Name)
	if pkg.Publisher == "" {
		id = strings.ToLower(pkg.Name)
	}
	return &models.ExtensionRecord{
		ID:        id,
		Version:   pkg.Version,
		Name:      pkg.Name,
		Publisher: pkg.Publisher,
		Ecosystem: eco,
	}
}

func collectJetBrainsPlugins() []models.ExtensionRecord {
	home, _ := os.UserHomeDir()
	var configBase string
	switch runtime.GOOS {
	case "darwin":
		configBase = filepath.Join(home, "Library", "Application Support", "JetBrains")
	case "linux":
		configBase = filepath.Join(home, ".config", "JetBrains")
	default:
		return nil
	}

	entries, err := os.ReadDir(configBase)
	if err != nil {
		return nil
	}

	var records []models.ExtensionRecord
	for _, ide := range entries {
		if !ide.IsDir() {
			continue
		}
		pluginsDir := filepath.Join(configBase, ide.Name(), "plugins")
		plugins, err := os.ReadDir(pluginsDir)
		if err != nil {
			continue
		}
		for _, p := range plugins {
			if !p.IsDir() {
				continue
			}
			records = append(records, models.ExtensionRecord{
				ID:        p.Name(),
				Name:      p.Name(),
				Version:   "unknown",
				Ecosystem: models.EcoJetBrains,
			})
		}
	}
	return records
}
