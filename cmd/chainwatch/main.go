package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/zainguard/chainwatch/pkg/inventory"
	"github.com/zainguard/chainwatch/pkg/models"
	"github.com/zainguard/chainwatch/pkg/output"
	"github.com/zainguard/chainwatch/pkg/scan"
)

const binaryVersion = "0.1.0"

func main() {
	var (
		outFormat      = flag.String("output", "table", "output format: table|json")
		noColor        = flag.Bool("no-color", false, "disable ANSI colors")
		socketKey      = flag.String("socket-key", "", "Socket.dev API key (or CHAINWATCH_SOCKET_KEY)")
		phylumKey      = flag.String("phylum-key", "", "Phylum.io API key (or CHAINWATCH_PHYLUM_KEY)")
		cacheDir       = flag.String("cache-dir", "", "cache directory (default ~/.chainwatch)")
		minSevStr      = flag.String("severity", "medium", "minimum severity to display: critical|high|medium|low")
		failOn         = flag.String("fail-on", "", "exit 1 if threats at this level exist: critical|high|medium|low")
		ecosystems     = flag.String("ecosystems", "", "comma-separated ecosystems to scan (default: all)")
		inventoryOnly  = flag.Bool("inventory", false, "print collected inventory as JSON and exit (no threat scan)")
		verbose        = flag.Bool("verbose", false, "print per-request debug lines to stderr")
		showVersion    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("chainwatch v%s\n", binaryVersion)
		os.Exit(0)
	}

	// Resolve API keys from flags then env.
	if *socketKey == "" {
		*socketKey = os.Getenv("CHAINWATCH_SOCKET_KEY")
	}
	if *phylumKey == "" {
		*phylumKey = os.Getenv("CHAINWATCH_PHYLUM_KEY")
	}

	// Resolve cache dir.
	if *cacheDir == "" {
		home, _ := os.UserHomeDir()
		*cacheDir = home + "/.chainwatch"
	}
	if err := os.MkdirAll(*cacheDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "chainwatch: cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Color: disable if flag set, or if not a TTY, or if NO_COLOR env set.
	if *noColor || os.Getenv("NO_COLOR") != "" {
		output.SetNoColor(true)
	}

	minSev := parseSeverity(*minSevStr)
	failSev := parseSeverity(*failOn)

	// Parse ecosystem filter.
	var ecoFilter map[models.Ecosystem]bool
	if *ecosystems != "" {
		ecoFilter = make(map[models.Ecosystem]bool)
		for _, e := range strings.Split(*ecosystems, ",") {
			ecoFilter[models.Ecosystem(strings.TrimSpace(e))] = true
		}
	}

	output.PrintHeader(os.Stderr)

	// Collect inventory.
	fmt.Fprintf(os.Stderr, "  Scanning packages and extensions...\n")
	inv := inventory.Collect()

	if ecoFilter != nil {
		inv = filterInventory(inv, ecoFilter)
	}

	fmt.Fprintf(os.Stderr, "  Collected %d packages, %d extensions\n",
		len(inv.Packages), len(inv.Extensions))

	if *inventoryOnly {
		switch *outFormat {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(inv); err != nil {
				fmt.Fprintf(os.Stderr, "chainwatch: json encode error: %v\n", err)
				os.Exit(1)
			}
		case "summary":
			output.PrintInventorySummary(os.Stdout, inv)
		default: // table
			output.PrintInventoryTable(os.Stdout, inv)
		}
		os.Exit(0)
	}

	// Build threat intel clients.
	clients := []scan.ThreatIntelClient{
		scan.NewSocketClient(*socketKey),
		scan.NewPhylumClient(*phylumKey),
		scan.NewFeedClient(scan.DefaultMalExtFeedURL, *cacheDir),
	}

	s := scan.NewScanner(*cacheDir, clients...)
	s.Progress = func(msg string) {
		output.PrintProgress(os.Stderr, msg)
	}
	if *verbose {
		s.Debug = func(msg string) {
			fmt.Fprintf(os.Stderr, "  [debug] %s\n", msg)
		}
	}

	ctx := context.Background()
	result, err := s.Run(ctx, inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chainwatch: scan error: %v\n", err)
		os.Exit(1)
	}

	switch *outFormat {
	case "json":
		if err := output.PrintJSON(os.Stdout, result, minSev); err != nil {
			fmt.Fprintf(os.Stderr, "chainwatch: json encode error: %v\n", err)
			os.Exit(1)
		}
	default:
		output.PrintTable(os.Stdout, result, minSev)
	}

	// CI gate: exit 1 if threats at or above failSev exist.
	if *failOn != "" {
		sevOrder := map[models.Severity]int{
			models.SeverityCritical: 4,
			models.SeverityHigh:     3,
			models.SeverityMedium:   2,
			models.SeverityLow:      1,
		}
		for _, f := range result.Findings {
			if sevOrder[f.Severity] >= sevOrder[failSev] {
				os.Exit(1)
			}
		}
	}
}

func parseSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func filterInventory(inv *models.Inventory, filter map[models.Ecosystem]bool) *models.Inventory {
	filtered := &models.Inventory{CollectedAt: inv.CollectedAt}
	for _, p := range inv.Packages {
		if filter[p.Ecosystem] {
			filtered.Packages = append(filtered.Packages, p)
		}
	}
	for _, e := range inv.Extensions {
		if filter[models.Ecosystem(e.Ecosystem)] {
			filtered.Extensions = append(filtered.Extensions, e)
		}
	}
	return filtered
}
