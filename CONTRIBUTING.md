# Contributing

## Scope

Chainwatch focuses on malicious intent detection, not vulnerability scanning (CVEs, license issues, or code quality). Keep contributions within that scope.

## Getting started

```bash
git clone https://github.com/zainguard/chainwatch.git
cd chainwatch
go build ./cmd/chainwatch
go test ./pkg/... -race
```

## Making changes

- Open an issue before starting significant work
- Fork the repo and create a branch from `main`
- Keep commits focused — one logical change per commit
- Run tests and lint before opening a PR

```bash
go test ./pkg/... -race -count=1
go vet ./...
```

## Pull requests

- Target `main`
- Describe what changed and why
- Link the related issue if one exists
- All CI checks must pass and at least one approval is required before merge

## Adding a threat intel source

Implement the `ThreatIntelClient` interface:

```go
type ThreatIntelClient interface {
    Name() string
    Scan(ctx context.Context, pkgs []models.PackageRecord, exts []models.ExtensionRecord) ([]models.Finding, error)
}
```

Then wire it into `NewScanner(...)` in `cmd/chainwatch/main.go`.

## Reporting security issues

Do not open a public issue for security vulnerabilities. Email security@zainguard.io instead.

## License

By contributing, you agree your changes will be licensed under the MIT license.
