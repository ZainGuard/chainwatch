package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

// localeMessage is one entry in a Chrome _locales/*/messages.json file.
type localeMessage struct {
	Message string `json:"message"`
}

// resolveExtName resolves __MSG_key__ placeholders in Chrome extension names.
// It reads _locales/en/messages.json inside versionDir, falling back to any
// available locale when English is absent.
func resolveExtName(name, versionDir string) string {
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") {
		return name
	}
	key := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__"))

	// Try English first, then any locale we can find.
	localesDir := filepath.Join(versionDir, "_locales")
	candidates := []string{
		filepath.Join(localesDir, "en", "messages.json"),
		filepath.Join(localesDir, "en_US", "messages.json"),
		filepath.Join(localesDir, "en_GB", "messages.json"),
	}
	// Append whatever else is in _locales as fallback.
	if entries, err := os.ReadDir(localesDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, filepath.Join(localesDir, e.Name(), "messages.json"))
			}
		}
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var msgs map[string]localeMessage
		if err := json.Unmarshal(data, &msgs); err != nil {
			continue
		}
		// Chrome does case-insensitive key matching; build a lowercase lookup map.
		lower := make(map[string]string, len(msgs))
		for k, v := range msgs {
			lower[strings.ToLower(k)] = v.Message
		}
		if msg, ok := lower[key]; ok && msg != "" {
			return msg
		}
	}
	return name // return raw placeholder if resolution fails
}

// chromiumBrowser describes a Chromium-based browser and its user data directory per OS.
type chromiumBrowser struct {
	eco         models.Ecosystem
	userDataDir string // path to the directory that contains profile subdirs
}

func chromiumBrowsers() []chromiumBrowser {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return []chromiumBrowser{
			{models.EcoChrome, filepath.Join(home, "Library/Application Support/Google/Chrome")},
			{models.EcoEdge, filepath.Join(home, "Library/Application Support/Microsoft Edge")},
			{models.EcoBrave, filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser")},
		}
	case "linux":
		return []chromiumBrowser{
			{models.EcoChrome, filepath.Join(home, ".config/google-chrome")},
			{models.EcoChrome, filepath.Join(home, ".config/chromium")},
			{models.EcoEdge, filepath.Join(home, ".config/microsoft-edge")},
			{models.EcoBrave, filepath.Join(home, ".config/BraveSoftware/Brave-Browser")},
		}
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		return []chromiumBrowser{
			{models.EcoChrome, filepath.Join(local, "Google/Chrome/User Data")},
			{models.EcoEdge, filepath.Join(local, "Microsoft/Edge/User Data")},
			{models.EcoBrave, filepath.Join(local, "BraveSoftware/Brave-Browser/User Data")},
		}
	}
	return nil
}

type profileDir struct {
	name   string // "Default", "Profile 3", etc.
	extDir string // full path to Extensions/
}

// profileDirs enumerates all profile directories inside a Chromium user data dir.
func profileDirs(userDataDir string) []profileDir {
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}
	var dirs []profileDir
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "Default" || strings.HasPrefix(name, "Profile ") {
			dirs = append(dirs, profileDir{
				name:   name,
				extDir: filepath.Join(userDataDir, name, "Extensions"),
			})
		}
	}
	return dirs
}

func collectBrowserExtensions() []models.ExtensionRecord {
	var records []models.ExtensionRecord
	for _, browser := range chromiumBrowsers() {
		for _, p := range profileDirs(browser.userDataDir) {
			records = append(records, scanChromiumExtensions(p.extDir, browser.eco, p.name)...)
		}
	}
	return records
}

type chromeManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func scanChromiumExtensions(dir string, eco models.Ecosystem, profile string) []models.ExtensionRecord {
	extDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []models.ExtensionRecord
	for _, extDir := range extDirs {
		if !extDir.IsDir() {
			continue
		}
		rec := parseBrowserExtensionDir(filepath.Join(dir, extDir.Name()), eco, profile)
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records
}

func parseBrowserExtensionDir(extIDDir string, eco models.Ecosystem, profile string) *models.ExtensionRecord {
	extID := filepath.Base(extIDDir)
	versionDirs, err := os.ReadDir(extIDDir)
	if err != nil {
		return nil
	}
	for _, vDir := range versionDirs {
		if !vDir.IsDir() {
			continue
		}
		versionDir := filepath.Join(extIDDir, vDir.Name())
		rec := parseChromeManifest(filepath.Join(versionDir, "manifest.json"), versionDir, extID, eco, profile)
		if rec != nil {
			return rec
		}
	}
	return nil
}

func parseChromeManifest(manifestPath, versionDir, extID string, eco models.Ecosystem, profile string) *models.ExtensionRecord {
	data, err := os.ReadFile(manifestPath)
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
		Name:      resolveExtName(m.Name, versionDir),
		Ecosystem: eco,
		Profile:   profile,
	}
}
