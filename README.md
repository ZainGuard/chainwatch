# Chainwatch

Supply chain threat scanner for developer machines. Inventories installed packages, IDE/browser extensions, and AI agent servers (MCP), then checks them against multiple threat intelligence sources to surface malicious components.

**This is not a CVE scanner.** Snyk, Dependabot, and Trivy already do that well. Chainwatch focuses exclusively on malicious intent: malware, hijacked packages, typosquatting, install-time code execution, and obfuscated behavior.

---

## What it detects

| Threat | Description |
|--------|-------------|
| `malware` | Package confirmed as malicious — credential stealer, backdoor, dropper |
| `supply-chain-attack` | Hijacked maintainer account or dependency confusion attack |
| `typosquatting` | Package name intentionally mimics a popular one (`requesets`, `lodahs`) |
| `protestware` | Package weaponized to harm users for political reasons |
| `install-script` | Runs arbitrary code at install time via pre/postinstall hooks |
| `obfuscated-code` | Source is deliberately obfuscated to hide behavior |
| `network-on-install` | Makes outbound network connections during installation |
| `data-exfiltration` | Sends env vars, SSH keys, or secrets to a remote server |
| `new-maintainer` | Package ownership changed recently — a common precursor to attacks |
| `high-churn` | Unusually high publish frequency or very new package |

## What it inventories

**Packages**

| Ecosystem | What's collected |
|-----------|-----------------|
| npm | Global installs + `package-lock.json` files under home dir |
| pip | Installed packages from all detected virtualenvs and site-packages |
| cargo | Packages from `Cargo.lock` files under home dir |
| go | Modules from `go.sum` files under home dir |
| brew | Installed Homebrew formulae (macOS only) |

**IDE extensions**

| Ecosystem | What's collected |
|-----------|-----------------|
| VS Code / Cursor / Windsurf / Zed | Installed extensions from `~/.vscode/extensions`, `~/.cursor/extensions`, etc. |
| JetBrains IDEs | Plugins from `~/Library/Application Support/JetBrains/` (macOS) or `~/.config/JetBrains/` (Linux) |

**Browser extensions**

| Ecosystem | What's collected |
|-----------|-----------------|
| Chrome / Edge / Brave | Extension ID + version from each browser profile |

**AI agent servers (MCP)**

| Source | What's collected |
|--------|-----------------|
| `~/.claude.json`, `~/.claude/.mcp.json` | Claude Code MCP servers |
| `claude_desktop_config.json` | Claude Desktop MCP servers |
| `.mcp.json` files under home dir | Project-level MCP servers |
| Claude Code plugins | Installed plugins from `~/.claude/plugins/` |

For `npx`-based MCP servers, the underlying npm package is also extracted and scanned for supply chain threats.

---

## Threat intelligence sources

Chainwatch queries multiple sources and correlates their results. The same component flagged by more than one source is shown once with combined attribution.

| Source | Coverage | Key |
|--------|----------|-----|
| [Socket.dev](https://socket.dev) | npm packages, VS Code extensions, Chrome extensions | `CHAINWATCH_SOCKET_KEY` |
| [Phylum.io](https://phylum.io) | pip, cargo, go, gem, npm | `CHAINWATCH_PHYLUM_KEY` |
| [malext-feed](https://github.com/toborrm9/malicious_extension_sentry) | Chrome/Edge/Brave extensions (IOC list) | — (no key required) |

The malext-feed is an open source IOC list of confirmed malicious Chrome extensions. A match means the extension is confirmed malicious. **No match does not mean the extension is safe** — the feed only covers extensions that have already been reported.

---

## Installation

### Go install

```bash
go install github.com/zainguard/chainwatch/cmd/chainwatch@latest
```

### Build from source

```bash
git clone https://github.com/zainguard/chainwatch.git
cd chainwatch
go build -o chainwatch ./cmd/chainwatch
sudo mv chainwatch /usr/local/bin/
```

> Homebrew tap and pre-built binaries are coming soon.

---

## Usage

### Basic scan

```bash
chainwatch
```

```
Chainwatch — Supply Chain Threat Scanner v0.1.0
  Scanning packages and extensions...
  Collected 2164 packages, 73 extensions
  Querying socket.dev (2164 packages, 73 extensions)...
  Querying phylum.io (0 packages, 0 extensions)...
  Querying malext-feed (0 packages, 73 extensions)...
  Cache: 2164 hits, 73 misses

CRITICAL — MALWARE (1)
  chrome   nkbihfbeogaeaoehlefnkodbefgpgknn  3.21.0
           [socket.dev, malext-feed]: Confirmed malicious browser extension
           https://socket.dev/chrome/package/nkbihfbeogaeaoehlefnkodbefgpgknn/overview/3.21.0

HIGH — SUPPLY CHAIN ATTACK (1)
  npm      event-stream                      3.3.6
           socket.dev: Malicious code injected by compromised maintainer

MEDIUM — TYPOSQUATTING (1)
  pip      requests-new                      2.28.0
           phylum.io: Similar name to popular package 'requests'

3 threats detected across 2164 packages, 73 extensions. [1200ms]
Severity breakdown: critical: 1, high: 1, medium: 1
```

### JSON output

```bash
chainwatch --output json
```

```json
{
  "scanned_at": "2026-05-23T10:00:00Z",
  "duration_ms": 3400,
  "summary": { "critical": 1, "high": 1, "medium": 2, "low": 0 },
  "findings": [
    {
      "ecosystem": "npm",
      "name": "flatmap-stream",
      "version": "0.1.1",
      "source": "socket.dev",
      "threat_type": "malware",
      "severity": "critical",
      "title": "Credential harvester targeting bitcoin wallets",
      "url": "https://socket.dev/npm/package/flatmap-stream/overview/0.1.1"
    }
  ]
}
```

Note: there is no `cves` field. This is by design.

### CI gating

```bash
# Exit 1 if any high or critical threat is found
chainwatch --fail-on high
echo "exit: $?"

# Pipe JSON to a file for artifact storage
chainwatch --fail-on high --output json | tee threats.json
```

```yaml
# GitHub Actions
- name: Supply chain threat scan
  env:
    CHAINWATCH_SOCKET_KEY: ${{ secrets.CHAINWATCH_SOCKET_KEY }}
  run: chainwatch --fail-on high --output json | tee threats.json
```

### View collected inventory

```bash
chainwatch --inventory                    # grouped table
chainwatch --inventory --output summary   # compact counts per ecosystem
chainwatch --inventory --output json      # machine-readable
```

### Scan specific ecosystems

```bash
chainwatch --ecosystems npm,pip
chainwatch --ecosystems vscode,chrome,brave,mcp
```

### Show only high and critical

```bash
chainwatch --severity high
```

### Debug mode (per-request details)

```bash
chainwatch --verbose
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `table` | Output format: `table`, `json`, or `summary` (inventory only) |
| `--severity` | `medium` | Minimum severity to display: `critical`, `high`, `medium`, `low` |
| `--fail-on` | — | Exit 1 if threats at this level or above exist |
| `--ecosystems` | all | Comma-separated ecosystems to scan |
| `--inventory` | false | Print collected inventory and exit (no threat scan) |
| `--verbose` | false | Print per-request debug lines to stderr |
| `--no-color` | false | Disable ANSI colors (`NO_COLOR` env also works) |
| `--socket-key` | — | Socket.dev API key (or `CHAINWATCH_SOCKET_KEY`) |
| `--phylum-key` | — | Phylum.io API key (or `CHAINWATCH_PHYLUM_KEY`) |
| `--cache-dir` | `~/.chainwatch` | Override cache directory |
| `--version` | — | Print version and exit |

---

## API keys

Chainwatch works without API keys, but coverage is significantly limited:

| | Without key | With key |
|--|-------------|----------|
| **Socket.dev** | ~10 req/min, npm only | 500 req/min, npm + VS Code + Chrome extensions |
| **Phylum.io** | Not queried | pip, cargo, go, gem, npm |
| **malext-feed** | Full coverage | — (no key needed) |

Chrome and VS Code extension scanning via Socket.dev requires a paid plan. Contact [sales@socket.dev](mailto:sales@socket.dev) for access.

### Getting keys

- **Socket.dev**: [socket.dev](https://socket.dev) → Settings → API Keys (free tier available)
- **Phylum.io**: [phylum.io](https://phylum.io) → Account Settings (free tier available)

### Setting keys

```bash
export CHAINWATCH_SOCKET_KEY=sk-...
export CHAINWATCH_PHYLUM_KEY=ph-...
chainwatch
```

Add to `~/.zshrc` or `~/.bashrc` to persist between sessions.

---

## Platform support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| npm packages | ✅ | ✅ | ✅ |
| pip packages | ✅ | ✅ | ✅ |
| cargo packages | ✅ | ✅ | ✅ |
| go modules | ✅ | ✅ | ✅ |
| Homebrew | ✅ | ✅ | — |
| VS Code / Cursor / Windsurf / Zed | ✅ | ✅ | ✅ |
| JetBrains plugins | ✅ | ✅ | — |
| Chrome / Edge / Brave extensions | ✅ | ✅ | ✅ |
| MCP servers | ✅ | ✅ | ✅ |
| Firefox extensions | planned | planned | planned |

macOS is the primary development platform and is most thoroughly tested.

---

## How it works

1. **Inventory** — Chainwatch reads package manager lock files, extension directories, browser profiles, and MCP config files. It makes no network calls during this step and does not modify any files.

2. **Threat intel** — Collected packages and extensions are batched and queried in parallel across all enabled sources. Socket.dev and Phylum.io analyze actual package behavior — not just CVE databases. The malext-feed is checked as a fast offline IOC lookup (feed is cached locally for 24 hours).

3. **Correlation** — When multiple sources flag the same component, findings are merged into a single result with combined source attribution (e.g. `[socket.dev, malext-feed]`). JSON output preserves individual source records for full fidelity.

4. **Cache** — API results are cached at `~/.chainwatch/threat-cache.json` with a 6-hour TTL. Repeat scans are near-instant for warm inventories.

5. **Output** — Findings are grouped by severity and threat type. Table format is human-readable; JSON is suitable for SIEM ingestion, Slack alerts, or CI gates.

### Cache files

```
~/.chainwatch/
  threat-cache.json    # API results (6h TTL)
  malext-feed.json     # IOC feed snapshot (24h TTL)
```

To force a fresh scan:

```bash
rm ~/.chainwatch/threat-cache.json
chainwatch
```

---

## Running on a schedule (macOS LaunchAgent)

```bash
cat > ~/Library/LaunchAgents/io.zainguard.chainwatch.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.zainguard.chainwatch</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/chainwatch</string>
    <string>--output</string>
    <string>json</string>
    <string>--no-color</string>
  </array>
  <key>StartInterval</key>
  <integer>3600</integer>
  <key>StandardOutPath</key>
  <string>/tmp/chainwatch.json</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/io.zainguard.chainwatch.plist
```

## Running on a schedule (Linux systemd timer)

```ini
# ~/.config/systemd/user/chainwatch.service
[Unit]
Description=Chainwatch supply chain scan

[Service]
ExecStart=/usr/local/bin/chainwatch --output json --no-color
StandardOutput=append:/tmp/chainwatch.json
```

```ini
# ~/.config/systemd/user/chainwatch.timer
[Unit]
Description=Run chainwatch hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable chainwatch.timer
systemctl --user start chainwatch.timer
```

---

## Use as a Go library

```go
import (
    "context"
    "os"

    "github.com/zainguard/chainwatch/pkg/inventory"
    "github.com/zainguard/chainwatch/pkg/scan"
)

inv := inventory.Collect()

cacheDir := os.ExpandEnv("$HOME/.chainwatch")
scanner := scan.NewScanner(
    cacheDir,
    scan.NewSocketClient(os.Getenv("CHAINWATCH_SOCKET_KEY")),
    scan.NewPhylumClient(os.Getenv("CHAINWATCH_PHYLUM_KEY")),
    scan.NewFeedClient(scan.DefaultMalExtFeedURL, cacheDir),
)

result, err := scanner.Run(context.Background(), inv)
```

Adding a new threat intel source requires implementing two methods and one line in `NewScanner(...)`:

```go
type ThreatIntelClient interface {
    Name() string
    Scan(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error)
}
```

The scanner handles parallelism, caching, deduplication, and debug wiring automatically.

---

## What chainwatch does NOT do

- **No CVE scanning** — use [Snyk](https://snyk.io), [Dependabot](https://github.com/dependabot), or [Trivy](https://trivy.dev)
- **No license compliance** — use [FOSSA](https://fossa.com) or [tldrlegal.com](https://tldrlegal.com)
- **No runtime monitoring** — it's a point-in-time scanner, not an agent
- **No network proxy or packet inspection** — purely filesystem-based, no traffic interception
- **No kernel modules or elevated privileges** — runs entirely as your user

---

## ZainGuard

Chainwatch is the open source core of [ZainGuard](https://zainguard.io) — a managed supply chain security platform for security teams. ZainGuard's agent builds on chainwatch to provide continuous monitoring, fleet-wide threat visibility, and policy enforcement across all developer machines in your organization.

---

## Contributing

Issues and PRs welcome. Please keep the scope focused on threat detection — not vulnerability scanning.

## License

MIT
