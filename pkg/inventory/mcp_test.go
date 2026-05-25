package inventory

import (
	"testing"
)

// --- splitAtVersion ---

func TestSplitAtVersion_Unscoped_WithVersion(t *testing.T) {
	name, ver := splitAtVersion("mcp-server@1.2.3")
	if name != "mcp-server" || ver != "1.2.3" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestSplitAtVersion_Unscoped_NoVersion(t *testing.T) {
	name, ver := splitAtVersion("mcp-server")
	if name != "mcp-server" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestSplitAtVersion_Scoped_WithVersion(t *testing.T) {
	name, ver := splitAtVersion("@scope/pkg@1.2.3")
	if name != "@scope/pkg" || ver != "1.2.3" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestSplitAtVersion_Scoped_NoVersion(t *testing.T) {
	name, ver := splitAtVersion("@scope/pkg")
	if name != "@scope/pkg" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestSplitAtVersion_Scoped_LatestTag(t *testing.T) {
	name, ver := splitAtVersion("@scope/pkg@latest")
	if name != "@scope/pkg" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestSplitAtVersion_AtSignedOnly(t *testing.T) {
	// Just "@" should be treated as unscoped with no version split
	name, ver := splitAtVersion("@")
	// "@" starts with @ but has no slash, so falls through to unscoped path
	// The unscoped path finds "@" at index 0, so name="" ver=""
	// Ensure no panic
	_ = name
	_ = ver
}

// --- extractNpxPackage ---

func TestExtractNpxPackage_BasicWithDashY(t *testing.T) {
	name, ver := extractNpxPackage([]string{"-y", "mcp-server"})
	if name != "mcp-server" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestExtractNpxPackage_ScopedWithVersion(t *testing.T) {
	name, ver := extractNpxPackage([]string{"-y", "@modelcontextprotocol/server-filesystem@1.0.0", "--port", "3000"})
	if name != "@modelcontextprotocol/server-filesystem" || ver != "1.0.0" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestExtractNpxPackage_SkipsLeadingFlags(t *testing.T) {
	name, ver := extractNpxPackage([]string{"--yes", "--", "@org/pkg@2.0.0"})
	// "--" is a flag-stopper but starts with "-", so it's skipped by our check
	// "@org/pkg@2.0.0" is the first non-flag arg
	if name != "@org/pkg" || ver != "2.0.0" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestExtractNpxPackage_EmptyArgs(t *testing.T) {
	name, ver := extractNpxPackage(nil)
	if name != "" || ver != "" {
		t.Errorf("expected empty for nil args, got name=%q ver=%q", name, ver)
	}
}

func TestExtractNpxPackage_AllFlags(t *testing.T) {
	name, ver := extractNpxPackage([]string{"-y", "--no-install", "-p"})
	if name != "" || ver != "" {
		t.Errorf("expected empty when all args are flags, got name=%q ver=%q", name, ver)
	}
}

// --- extractUvxPackage ---

func TestExtractUvxPackage_WithVersion(t *testing.T) {
	name, ver := extractUvxPackage([]string{"mcp-proxy-for-aws@0.4.0"})
	if name != "mcp-proxy-for-aws" || ver != "0.4.0" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestExtractUvxPackage_NoVersion_DefaultsToLatest(t *testing.T) {
	name, ver := extractUvxPackage([]string{"mcp-server-git"})
	if name != "mcp-server-git" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

func TestExtractUvxPackage_SkipsDashFlags(t *testing.T) {
	// Single-dash flags are skipped; first non-flag arg is the package name
	name, ver := extractUvxPackage([]string{"-q", "my-mcp-tool"})
	if name != "my-mcp-tool" || ver != "latest" {
		t.Errorf("got name=%q ver=%q", name, ver)
	}
}

// --- resolveName ---

func TestResolveName_NpxCommand(t *testing.T) {
	def := mcpServerDef{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.0.0"}}
	got := resolveName(def)
	if got != "@modelcontextprotocol/server-filesystem@1.0.0" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_NpxCommand_NoVersion(t *testing.T) {
	def := mcpServerDef{Command: "npx", Args: []string{"-y", "mcp-server"}}
	got := resolveName(def)
	// No version tag → just the name (no "@latest" suffix)
	if got != "mcp-server" {
		t.Errorf("got %q, want %q", got, "mcp-server")
	}
}

func TestResolveName_HTTPType(t *testing.T) {
	def := mcpServerDef{Type: "http", URL: "https://mcp.example.com/api"}
	got := resolveName(def)
	if got != "https://mcp.example.com/api" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_SSEType(t *testing.T) {
	def := mcpServerDef{Type: "sse", URL: "https://mcp.example.com/sse"}
	got := resolveName(def)
	if got != "https://mcp.example.com/sse" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_NodeCommand(t *testing.T) {
	def := mcpServerDef{Command: "node", Args: []string{"/usr/local/lib/server.js"}}
	got := resolveName(def)
	if got != "node: /usr/local/lib/server.js" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_PythonModule(t *testing.T) {
	def := mcpServerDef{Command: "python3", Args: []string{"-m", "mcp_server_git"}}
	got := resolveName(def)
	if got != "python: mcp_server_git" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_UvxCommand(t *testing.T) {
	def := mcpServerDef{Command: "uvx", Args: []string{"mcp-proxy@0.4.0"}}
	got := resolveName(def)
	if got != "mcp-proxy@0.4.0" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_UnknownCommand(t *testing.T) {
	def := mcpServerDef{Command: "my-custom-binary", Args: []string{"serve"}}
	got := resolveName(def)
	if got != "my-custom-binary: serve" {
		t.Errorf("got %q", got)
	}
}

func TestResolveName_UnknownCommand_NoArgs(t *testing.T) {
	def := mcpServerDef{Command: "my-binary"}
	got := resolveName(def)
	if got != "my-binary" {
		t.Errorf("got %q", got)
	}
}

// --- buildMCPRecord ---

func TestBuildMCPRecord_NpxEmitsPackageRecord(t *testing.T) {
	def := mcpServerDef{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-git@1.0.0"}}
	ext, pkg := buildMCPRecord("git-server", def, "~/.claude.json")
	if pkg == nil {
		t.Fatal("expected PackageRecord for npx command")
	}
	if pkg.Name != "@modelcontextprotocol/server-git" {
		t.Errorf("package name: got %q", pkg.Name)
	}
	if pkg.Version != "1.0.0" {
		t.Errorf("package version: got %q", pkg.Version)
	}
	if ext.ID != "git-server" {
		t.Errorf("extension ID: got %q", ext.ID)
	}
}

func TestBuildMCPRecord_UvxEmitsPipPackageRecord(t *testing.T) {
	def := mcpServerDef{Command: "uvx", Args: []string{"mcp-server-git"}}
	_, pkg := buildMCPRecord("git-server", def, "~/.claude.json")
	if pkg == nil {
		t.Fatal("expected PackageRecord for uvx command")
	}
	if string(pkg.Ecosystem) != "pip" {
		t.Errorf("expected pip ecosystem, got %q", pkg.Ecosystem)
	}
}

func TestBuildMCPRecord_HTTPType_NoPackage(t *testing.T) {
	def := mcpServerDef{Type: "http", URL: "https://mcp.example.com/api"}
	_, pkg := buildMCPRecord("remote-server", def, "~/.claude.json")
	if pkg != nil {
		t.Error("expected no PackageRecord for HTTP-type MCP server")
	}
}

// --- splitPluginKey ---

func TestSplitPluginKey_WithMarketplace(t *testing.T) {
	name, marketplace := splitPluginKey("my-plugin@npm")
	if name != "my-plugin" || marketplace != "npm" {
		t.Errorf("got name=%q marketplace=%q", name, marketplace)
	}
}

func TestSplitPluginKey_NoMarketplace(t *testing.T) {
	name, marketplace := splitPluginKey("simple-plugin")
	if name != "simple-plugin" || marketplace != "" {
		t.Errorf("got name=%q marketplace=%q", name, marketplace)
	}
}
