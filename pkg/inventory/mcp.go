package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

// mcpServersFile is the shared structure for all MCP config files.
// ~/.claude.json, ~/.claude/.mcp.json, and .mcp.json all use mcpServers at the top level.
type mcpServersFile struct {
	MCPServers           map[string]mcpServerDef `json:"mcpServers"`
	ClaudeAIMCPConnected []string                `json:"claudeAiMcpEverConnected"`
}

type mcpServerDef struct {
	Type    string   `json:"type"`    // "stdio" (default), "http", "sse"
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"` // for http/sse
}

// claudePluginsManifest is ~/.claude/plugins/installed_plugins.json
type claudePluginsManifest struct {
	Plugins map[string][]claudePluginInstall `json:"plugins"`
}

type claudePluginInstall struct {
	Version string `json:"version"`
}

func collectMCPComponents() ([]models.ExtensionRecord, []models.PackageRecord) {
	var exts []models.ExtensionRecord
	var pkgs []models.PackageRecord
	seen := make(map[string]bool) // deduplicate by "key|source"

	home, _ := os.UserHomeDir()

	addFromFile := func(path string) {
		parseMCPFile(path, seen, &exts, &pkgs)
	}

	// Primary user MCP config — this is what /mcp shows in Claude Code
	addFromFile(filepath.Join(home, ".claude.json"))

	// Global project-scoped MCP config
	addFromFile(filepath.Join(home, ".claude", ".mcp.json"))

	// Claude Desktop (macOS + Linux)
	addFromFile(filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
	addFromFile(filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))

	// Project-level .mcp.json files under home dir
	walkForLockfiles(home, ".mcp.json", func(path string) {
		addFromFile(path)
	})

	// Claude Code plugins (installed_plugins.json has real versions)
	exts = append(exts, collectClaudePlugins()...)

	return exts, pkgs
}

func parseMCPFile(path string, seen map[string]bool, exts *[]models.ExtensionRecord, pkgs *[]models.PackageRecord) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg mcpServersFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}

	source := shortenHomePath(path)

	for name, def := range cfg.MCPServers {
		dedupeKey := name + "|" + resolveName(def)
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		ext, npmPkg := buildMCPRecord(name, def, source)
		*exts = append(*exts, ext)
		if npmPkg != nil {
			*pkgs = append(*pkgs, *npmPkg)
		}
	}

	// claude.ai hosted MCPs (Atlassian, Gmail, Google Calendar, etc.)
	for _, hostedName := range cfg.ClaudeAIMCPConnected {
		dedupeKey := "claude.ai|" + hostedName
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true
		*exts = append(*exts, models.ExtensionRecord{
			ID:        hostedName,
			Name:      hostedName,
			Version:   "hosted",
			Ecosystem: models.EcoMCP,
			Profile:   "claude.ai",
		})
	}
}

// buildMCPRecord constructs an ExtensionRecord and optionally a PackageRecord for
// npm/uvx-based servers that can be scanned for threats.
func buildMCPRecord(serverKey string, def mcpServerDef, source string) (models.ExtensionRecord, *models.PackageRecord) {
	ext := models.ExtensionRecord{
		ID:        serverKey,
		Name:      resolveName(def),
		Version:   "unknown",
		Ecosystem: models.EcoMCP,
		Profile:   source,
	}

	// npm packages via npx — emit PackageRecord for Socket.dev scanning
	if def.Command == "npx" || def.Command == "pnpx" || def.Command == "bunx" {
		pkgName, pkgVer := extractNpxPackage(def.Args)
		if pkgName != "" {
			return ext, &models.PackageRecord{
				Name:      pkgName,
				Version:   pkgVer,
				Ecosystem: models.EcoNpm,
				Path:      "mcp",
			}
		}
	}

	// uvx packages — emit as pip PackageRecord for Phylum scanning
	if def.Command == "uvx" || def.Command == "uv" {
		pkgName, _ := extractUvxPackage(def.Args)
		if pkgName != "" {
			return ext, &models.PackageRecord{
				Name:      pkgName,
				Version:   "latest",
				Ecosystem: models.EcoPip,
				Path:      "mcp",
			}
		}
	}

	return ext, nil
}

// resolveName produces a clean human-readable name from an MCP server definition.
func resolveName(def mcpServerDef) string {
	// Remote HTTP/SSE server
	if def.Type == "http" || def.Type == "sse" || def.URL != "" {
		return def.URL
	}

	switch def.Command {
	case "npx", "pnpx", "bunx":
		name, ver := extractNpxPackage(def.Args)
		if name != "" {
			if ver != "" && ver != "latest" {
				return name + "@" + ver
			}
			return name
		}

	case "uvx", "uv":
		name, ver := extractUvxPackage(def.Args)
		if name != "" {
			if ver != "" && ver != "latest" {
				return name + "@" + ver
			}
			return name
		}

	case "node", "deno":
		// node /path/to/server.js or node ./server.js
		if len(def.Args) > 0 {
			return "node: " + shortenHomePath(def.Args[0])
		}

	case "python", "python3":
		// python -m mcp_server or python /path/to/server.py
		args := skipFlags(def.Args)
		if len(args) > 0 {
			if args[0] == "-m" && len(args) > 1 {
				return "python: " + args[1]
			}
			return "python: " + shortenHomePath(args[0])
		}

	case "bun":
		// bun run ./index.ts  or  bun run --cwd ${PLUGIN_ROOT} start
		// Find the first concrete file/script arg, skipping "run", flags, and template vars.
		for _, arg := range def.Args {
			if arg == "run" || strings.HasPrefix(arg, "-") || strings.Contains(arg, "${") {
				continue
			}
			// Looks like a path or filename — use it
			if strings.Contains(arg, "/") || strings.Contains(arg, ".") {
				return "bun: " + shortenHomePath(arg)
			}
		}
		// No concrete path found (plugin entry point) — server key is the name

	default:
		if def.Command != "" {
			cmd := def.Command
			// Use just the binary name for long/relative paths
			if strings.Contains(cmd, "/") {
				cmd = filepath.Base(cmd)
			}
			args := skipFlags(def.Args)
			if len(args) > 0 && !strings.Contains(args[0], "${") {
				return cmd + ": " + shortenHomePath(args[0])
			}
			return cmd
		}
	}

	return ""
}

// extractNpxPackage finds the npm package name and version from npx args.
// e.g. ["-y", "@scope/pkg@1.2.3", "/path"] → ("@scope/pkg", "1.2.3")
// e.g. ["-y", "mcp-server", "--port", "3000"] → ("mcp-server", "latest")
func extractNpxPackage(args []string) (name, version string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || arg == "--" {
			continue
		}
		// Split name@version but handle scoped packages: @scope/pkg@ver
		name, version = splitAtVersion(arg)
		return
	}
	return "", ""
}

// extractUvxPackage finds the package name and version from uvx args.
// e.g. ["mcp-proxy-for-aws@latest", "--flag"] → ("mcp-proxy-for-aws", "latest")
func extractUvxPackage(args []string) (name, version string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		name, version = splitAtVersion(arg)
		if version == "" {
			version = "latest"
		}
		return
	}
	return "", ""
}

// splitAtVersion splits "package@version" respecting scoped npm names like "@scope/pkg@ver".
func splitAtVersion(s string) (name, version string) {
	// Scoped npm: @scope/pkg@ver — find the @ after the first /
	if strings.HasPrefix(s, "@") {
		if slash := strings.Index(s, "/"); slash != -1 {
			if at := strings.Index(s[slash:], "@"); at != -1 {
				return s[:slash+at], s[slash+at+1:]
			}
		}
		return s, "latest"
	}
	// Unscoped: pkg@ver
	if at := strings.Index(s, "@"); at != -1 {
		return s[:at], s[at+1:]
	}
	return s, "latest"
}

// skipFlags returns args with leading flag arguments removed.
func skipFlags(args []string) []string {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			return args[i:]
		}
	}
	return nil
}

func collectClaudePlugins() []models.ExtensionRecord {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var manifest claudePluginsManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	var records []models.ExtensionRecord
	for pluginKey, installs := range manifest.Plugins {
		if len(installs) == 0 {
			continue
		}
		name, marketplace := splitPluginKey(pluginKey)
		records = append(records, models.ExtensionRecord{
			ID:        pluginKey,
			Name:      name,
			Version:   installs[0].Version,
			Publisher: marketplace,
			Ecosystem: models.EcoMCP,
			Profile:   "claude-plugin",
		})
	}
	return records
}

func splitPluginKey(key string) (name, marketplace string) {
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

func shortenHomePath(p string) string {
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}
