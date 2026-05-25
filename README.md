# Chainwatch

Supply chain threat scanner for developer machines. Inventories installed packages, IDE extensions, browser extensions, and MCP servers, then checks them against threat intelligence sources to surface malicious components.

Focuses on malicious intent: malware, hijacked packages, typosquatting, and obfuscated behavior. Not a CVE scanner.

---

## What it detects

| Threat | Description |
|--------|-------------|
| `malware` | Confirmed malicious package |
| `supply-chain-attack` | Hijacked maintainer or dependency confusion |
| `typosquatting` | Name mimics a popular package |
| `protestware` | Package weaponized for political reasons |
| `install-script` | Runs code at install time |
| `obfuscated-code` | Source deliberately obfuscated |
| `network-on-install` | Makes outbound connections during install |
| `data-exfiltration` | Sends env vars, SSH keys, or secrets externally |
| `new-maintainer` | Package ownership changed recently |
| `high-churn` | Unusually high publish frequency |

## What it inventories

**Packages**

| Ecosystem | Source |
|-----------|--------|
| npm | Global installs + `package-lock.json` files |
| pip | Virtualenvs and site-packages |
| cargo | `Cargo.lock` files |
| go | `go.sum` files |
| brew | Installed Homebrew formulae (macOS) |

**Extensions**

| Ecosystem | Source |
|-----------|--------|
| VS Code / Cursor / Windsurf / Zed | `~/.vscode/extensions`, `~/.cursor/extensions`, etc. |
| JetBrains IDEs | `~/Library/Application Support/JetBrains/` (macOS), `~/.config/JetBrains/` (Linux) |
| Chrome / Edge / Brave | Extension ID + version from each browser profile |

**MCP servers**

| Source | What's collected |
|--------|-----------------|
| `~/.claude.json`, `~/.claude/.mcp.json` | Claude Code MCP servers |
| `claude_desktop_config.json` | Claude Desktop MCP servers |
| `.mcp.json` files under home dir | Project-level MCP servers |
| `~/.claude/plugins/` | Claude Code plugins |

For `npx`-based MCP servers, the underlying npm package is also scanned.

---

## Threat intelligence sources

| Source | Coverage | Key |
|--------|----------|-----|
| [Socket.dev](https://socket.dev) | npm, VS Code extensions, Chrome extensions | `CHAINWATCH_SOCKET_KEY` |
| [Phylum.io](https://phylum.io) | pip, cargo, go, gem, npm | `CHAINWATCH_PHYLUM_KEY` |
| [malext-feed](https://github.com/toborrm9/malicious_extension_sentry) | Chrome/Edge/Brave extensions | none |

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

```bash
chainwatch
```

```
Chainwatch v0.1.0
  Scanning packages and extensions...
  Collected 2164 packages, 73 extensions
  Querying socket.dev (2164 packages, 73 extensions)...
  Querying phylum.io (0 packages, 0 extensions)...
  Querying malext-feed (0 packages, 73 extensions)...
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

### JSON output

```bash
chainwatch --output json
```

### CI gating

```bash
chainwatch --fail-on high
chainwatch --fail-on high --output json | tee threats.json
```

```yaml
# GitHub Actions
- name: Supply chain threat scan
  env:
    CHAINWATCH_SOCKET_KEY: ${{ secrets.CHAINWATCH_SOCKET_KEY }}
  run: chainwatch --fail-on high --output json | tee threats.json
```

### Inventory only

```bash
chainwatch --inventory
chainwatch --inventory --output json
```

### Filter by ecosystem or severity

```bash
chainwatch --ecosystems npm,pip
chainwatch --severity high
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `table` | `table`, `json`, or `summary` (inventory only) |
| `--severity` | `medium` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `--fail-on` | | Exit 1 if threats at this level or above exist |
| `--ecosystems` | all | Comma-separated list of ecosystems to scan |
| `--inventory` | false | Print inventory and exit without scanning |
| `--verbose` | false | Print per-request debug lines to stderr |
| `--no-color` | false | Disable ANSI colors (`NO_COLOR` env also works) |
| `--socket-key` | | Socket.dev API key (or `CHAINWATCH_SOCKET_KEY`) |
| `--phylum-key` | | Phylum.io API key (or `CHAINWATCH_PHYLUM_KEY`) |
| `--cache-dir` | `~/.chainwatch` | Override cache directory |
| `--version` | | Print version and exit |

---

## API keys

Both services have a free tier.

| | Without key | With key |
|--|-------------|----------|
| Socket.dev | ~10 req/min, npm only | 500 req/min, npm + VS Code + Chrome |
| Phylum.io | Not queried | pip, cargo, go, gem, npm |
| malext-feed | Full coverage | No key needed |

```bash
export CHAINWATCH_SOCKET_KEY=sk-...
export CHAINWATCH_PHYLUM_KEY=ph-...
```

Add to `~/.zshrc` or `~/.bashrc` to persist.

---

## Platform support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| npm | ✅ | ✅ | ✅ |
| pip | ✅ | ✅ | ✅ |
| cargo | ✅ | ✅ | ✅ |
| go | ✅ | ✅ | ✅ |
| Homebrew | ✅ | ✅ | |
| VS Code / Cursor / Windsurf / Zed | ✅ | ✅ | ✅ |
| JetBrains | ✅ | ✅ | |
| Chrome / Edge / Brave | ✅ | ✅ | ✅ |
| MCP servers | ✅ | ✅ | ✅ |
| Firefox | planned | planned | planned |

---

## Cache

Results are cached at `~/.chainwatch/` with a 6-hour TTL. The malext feed snapshot is cached for 24 hours.

```
~/.chainwatch/
  threat-cache.json
  malext-feed.json
```

To force a fresh scan:

```bash
rm ~/.chainwatch/threat-cache.json && chainwatch
```

---

## Schedule (macOS)

```bash
cat > ~/Library/LaunchAgents/io.zainguard.chainwatch.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.zainguard.chainwatch</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/chainwatch</string>
    <string>--output</string><string>json</string>
    <string>--no-color</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>StandardOutPath</key><string>/tmp/chainwatch.json</string>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/io.zainguard.chainwatch.plist
```

## Schedule (Linux)

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
systemctl --user enable --now chainwatch.timer
```

---

## Go library

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

New threat intel sources can be added by implementing the `ThreatIntelClient` interface:

```go
type ThreatIntelClient interface {
    Name() string
    Scan(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error)
}
```

---

## Out of scope

- CVE scanning: use [Snyk](https://snyk.io), [Dependabot](https://github.com/dependabot), or [Trivy](https://trivy.dev)
- License compliance: use [FOSSA](https://fossa.com)
- Runtime monitoring: chainwatch is a point-in-time scanner
- Network traffic inspection: filesystem-based only, no packet capture
- Elevated privileges: runs as your current user

---

## ZainGuard

Chainwatch is the open source core of [ZainGuard](https://zainguard.io), a supply chain security platform for security teams.

---

## Contributing

Issues and PRs welcome. Keep scope focused on threat detection, not vulnerability scanning.

## License

MIT
