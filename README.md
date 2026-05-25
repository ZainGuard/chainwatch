<a href="https://www.buymeacoffee.com/zainguard" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

# Chainwatch

Supply chain threat scanner for developer machines. Scans installed packages, IDE extensions, browser extensions, and MCP servers against threat intelligence sources to find malicious components.

Not a CVE scanner. Focuses on malware, hijacked packages, typosquatting, and obfuscated behavior.

---

## Install

```bash
go install github.com/zainguard/chainwatch/cmd/chainwatch@latest
```

Or build from source:

```bash
git clone https://github.com/zainguard/chainwatch.git
cd chainwatch && go build -o chainwatch ./cmd/chainwatch
```

> Homebrew and pre-built binaries coming soon.

---

## Usage

```bash
chainwatch
```

```
Chainwatch v0.1.0
  Scanning packages and extensions...
  Collected 2164 packages, 73 extensions
  Querying socket.dev...
  Querying phylum.io...
  Querying malext-feed...
  Cache: 2164 hits, 73 misses

CRITICAL (1)
  chrome  nkbihfbeogaeaoehlefnkodbefgpgknn  3.21.0
          [socket.dev, malext-feed]: Confirmed malicious browser extension

HIGH (1)
  npm     event-stream  3.3.6
          socket.dev: Malicious code injected by compromised maintainer

MEDIUM (1)
  pip     requests-new  2.28.0
          phylum.io: Similar name to popular package 'requests'

3 threats across 2164 packages, 73 extensions [1200ms]
```

### Common options

```bash
chainwatch --output json                    # JSON output
chainwatch --fail-on high                   # exit 1 if high/critical found
chainwatch --severity high                  # show high and critical only
chainwatch --ecosystems npm,pip             # scan specific ecosystems
chainwatch --inventory                      # print inventory without scanning
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `table` | `table` or `json` |
| `--severity` | `medium` | Minimum severity to show |
| `--fail-on` | | Exit 1 if threats at this level or above are found |
| `--ecosystems` | all | Comma-separated ecosystems to scan |
| `--inventory` | false | Print inventory and exit |
| `--no-color` | false | Disable ANSI colors |
| `--socket-key` | | Socket.dev API key |
| `--phylum-key` | | Phylum.io API key |
| `--cache-dir` | `~/.chainwatch` | Override cache directory |
| `--version` | | Print version |

---

## API keys

| Source | Free tier | Env var |
|--------|-----------|---------|
| [Socket.dev](https://socket.dev) | Yes | `CHAINWATCH_SOCKET_KEY` |
| [Phylum.io](https://phylum.io) | Yes | `CHAINWATCH_PHYLUM_KEY` |
| malext-feed | No key needed | |

Without keys, Socket.dev is rate-limited and Phylum is skipped entirely.

```bash
export CHAINWATCH_SOCKET_KEY=sk-...
export CHAINWATCH_PHYLUM_KEY=ph-...
```

---

## What it scans

**Packages:** npm, pip, cargo, go, brew

**Extensions:** VS Code, Cursor, Windsurf, Zed, JetBrains, Chrome, Edge, Brave

**MCP servers:** Claude Code, Claude Desktop, project-level `.mcp.json` files

Results are cached at `~/.chainwatch/` with a 6-hour TTL.

---

## Platform support

| | macOS | Linux | Windows |
|--|-------|-------|---------|
| npm, pip, cargo, go | yes | yes | yes |
| Homebrew | yes | yes | |
| VS Code / Cursor / Windsurf / Zed | yes | yes | yes |
| JetBrains | yes | yes | |
| Chrome / Edge / Brave | yes | yes | yes |
| MCP servers | yes | yes | yes |

---

## Out of scope

CVE scanning (use Snyk, Dependabot, or Trivy), license compliance, runtime monitoring, and network traffic inspection.

---

## Zainguard

Chainwatch is the open source core of [Zainguard](https://zainguard.com), a multi-tenant SaaS security and compliance platform.

---

## Contributing

Issues and PRs welcome. Keep scope focused on threat detection.

## License

MIT
