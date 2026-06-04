package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/zainguard/chainwatch/pkg/models"
)

const version = "0.1.0"

var (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorRed     = "\033[31m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorBoldRed = "\033[1;31m"
	colorBoldYel = "\033[1;33m"
)

func SetNoColor(v bool) {
	if v {
		colorReset = ""
		colorBold = ""
		colorRed = ""
		colorCyan = ""
		colorGray = ""
		colorBoldRed = ""
		colorBoldYel = ""
	}
}

// PrintHeader writes the scan header to stderr.
func PrintHeader(out io.Writer) {
	fmt.Fprintf(out, "%sChainwatch%s — Supply Chain Threat Scanner v%s\n", colorBold, colorReset, version)
}

// PrintProgress writes a progress line to stderr.
func PrintProgress(out io.Writer, msg string) {
	fmt.Fprintf(out, "  %s%s%s\n", colorGray, msg, colorReset)
}

// PrintTable writes the threat table to stdout.
func PrintTable(out io.Writer, result *models.ScanResult, minSev models.Severity) {
	filtered := filterBySeverity(result.Findings, minSev)

	if len(filtered) == 0 {
		fmt.Fprintf(out, "\n%s✓ No threats detected%s across %d packages, %d extensions.\n",
			colorCyan, colorReset,
			len(result.Inventory.Packages),
			len(result.Inventory.Extensions))
		fmt.Fprintf(out, "  Run with --inventory to see everything that was scanned.\n")
		return
	}

	// Group by severity then threat type.
	bySev := groupBySeverity(filtered)
	sevOrder := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}

	fmt.Fprintln(out)
	for _, sev := range sevOrder {
		group, ok := bySev[sev]
		if !ok {
			continue
		}
		byThreat := groupByThreat(group)
		for threat, finds := range byThreat {
			merged := mergeByComponent(finds)
			label := fmt.Sprintf("%s — %s (%d)", strings.ToUpper(string(sev)), strings.ToUpper(string(threat)), len(merged))
			fmt.Fprintf(out, "%s%s%s\n", sevColor(sev), label, colorReset)
			for _, m := range merged {
				fmt.Fprintf(out, "  %-8s %-30s %-12s\n",
					string(m.Ecosystem),
					m.Name,
					m.Version)
				// Show source attribution: single source or [source1, source2, ...]
				sourceTag := m.Sources[0]
				if len(m.Sources) > 1 {
					sourceTag = fmt.Sprintf("[%s]", strings.Join(m.Sources, ", "))
				}
				if m.Description != "" {
					fmt.Fprintf(out, "  %s%s: %s%s\n", colorGray, sourceTag, m.Description, colorReset)
				}
				if m.URL != "" {
					fmt.Fprintf(out, "  %s%s%s\n", colorGray, m.URL, colorReset)
				}
			}
			fmt.Fprintln(out)
		}
	}

	// Count unique components (not raw findings) for the summary line
	total := len(mergeByComponent(filtered))
	counts := countBySeverity(filtered)
	fmt.Fprintf(out, "%d threat%s detected across %d packages, %d extensions. [%dms]\n",
		total, plural(total),
		len(result.Inventory.Packages),
		len(result.Inventory.Extensions),
		result.DurationMs)

	parts := []string{}
	for _, sev := range sevOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", sev, n))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(out, "Severity breakdown: %s\n", strings.Join(parts, ", "))
	}
}

// mergedFinding is a Finding collapsed across sources for table display.
type mergedFinding struct {
	models.Finding
	Sources []string // all source names that flagged this component
}

// mergeByComponent collapses findings with the same ecosystem+name+version+threat_type
// into a single row, combining their sources. The description and URL come from the
// highest-severity finding (or the one with the most informative description).
func mergeByComponent(findings []models.Finding) []mergedFinding {
	type key struct {
		eco     models.Ecosystem
		name    string
		version string
		threat  models.ThreatType
	}

	order := []key{}
	groups := map[key][]models.Finding{}

	for _, f := range findings {
		k := key{f.Ecosystem, f.Name, f.Version, f.ThreatType}
		if _, exists := groups[k]; !exists {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}

	out := make([]mergedFinding, 0, len(order))
	for _, k := range order {
		group := groups[k]
		best := group[0]
		sources := make([]string, 0, len(group))
		seen := map[string]bool{}
		for _, f := range group {
			if !seen[f.Source] {
				sources = append(sources, f.Source)
				seen[f.Source] = true
			}
			// Prefer longer descriptions and higher-severity sources
			if len(f.Description) > len(best.Description) {
				best = f
			}
		}
		out = append(out, mergedFinding{Finding: best, Sources: sources})
	}
	return out
}

func sevColor(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return colorBoldRed
	case models.SeverityHigh:
		return colorRed
	case models.SeverityMedium:
		return colorBoldYel
	default:
		return colorCyan
	}
}

func filterBySeverity(findings []models.Finding, min models.Severity) []models.Finding {
	order := map[models.Severity]int{
		models.SeverityCritical: 4,
		models.SeverityHigh:     3,
		models.SeverityMedium:   2,
		models.SeverityLow:      1,
	}
	minVal := order[min]
	var out []models.Finding
	for _, f := range findings {
		if order[f.Severity] >= minVal {
			out = append(out, f)
		}
	}
	return out
}

func groupBySeverity(findings []models.Finding) map[models.Severity][]models.Finding {
	m := make(map[models.Severity][]models.Finding)
	for _, f := range findings {
		m[f.Severity] = append(m[f.Severity], f)
	}
	return m
}

func groupByThreat(findings []models.Finding) map[models.ThreatType][]models.Finding {
	m := make(map[models.ThreatType][]models.Finding)
	for _, f := range findings {
		m[f.ThreatType] = append(m[f.ThreatType], f)
	}
	return m
}

func countBySeverity(findings []models.Finding) map[models.Severity]int {
	m := make(map[models.Severity]int)
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// PrintInventoryTable prints the inventory as a grouped, human-readable table.
func PrintInventoryTable(out io.Writer, inv *models.Inventory) {
	ecoOrder := []models.Ecosystem{
		models.EcoNpm, models.EcoPip, models.EcoCargo, models.EcoGo, models.EcoBrew,
		models.EcoVSCode, models.EcoCursor, models.EcoWindsurf, models.EcoZed, models.EcoJetBrains,
		models.EcoChrome, models.EcoEdge, models.EcoBrave, models.EcoFirefox,
		models.EcoMCP,
	}

	// Group packages by ecosystem.
	pkgByEco := make(map[models.Ecosystem][]models.PackageRecord)
	for _, p := range inv.Packages {
		pkgByEco[p.Ecosystem] = append(pkgByEco[p.Ecosystem], p)
	}
	extByEco := make(map[models.Ecosystem][]models.ExtensionRecord)
	for _, e := range inv.Extensions {
		extByEco[e.Ecosystem] = append(extByEco[e.Ecosystem], e)
	}

	fmt.Fprintf(out, "\n%s%s PACKAGES (%d)%s\n", colorBold, colorCyan, len(inv.Packages), colorReset)
	for _, eco := range ecoOrder {
		pkgs, ok := pkgByEco[eco]
		if !ok {
			continue
		}
		sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
		fmt.Fprintf(out, "\n  %s%s%s (%d)\n", colorBold, strings.ToUpper(string(eco)), colorReset, len(pkgs))
		for _, p := range pkgs {
			path := ""
			if p.Path != "" {
				path = fmt.Sprintf("  %s%s%s", colorGray, shortenPath(p.Path), colorReset)
			}
			fmt.Fprintf(out, "    %-45s %s%s%s%s\n",
				p.Name,
				colorGray, p.Version, colorReset,
				path)
		}
	}

	fmt.Fprintf(out, "\n%s%s EXTENSIONS (%d)%s\n", colorBold, colorCyan, len(inv.Extensions), colorReset)
	for _, eco := range ecoOrder {
		exts, ok := extByEco[eco]
		if !ok {
			continue
		}
		sort.Slice(exts, func(i, j int) bool {
			if exts[i].Name != exts[j].Name {
				return exts[i].Name < exts[j].Name
			}
			return exts[i].Version < exts[j].Version
		})
		fmt.Fprintf(out, "\n  %s%s%s (%d)\n", colorBold, strings.ToUpper(string(eco)), colorReset, len(exts))
		for _, e := range exts {
			name := e.Name
			if name == "" {
				name = e.ID
			}
			id := ""
			if e.ID != "" && e.ID != name {
				id = fmt.Sprintf("  %s%s%s", colorGray, e.ID, colorReset)
			}
			profile := ""
			if e.Profile != "" {
				profile = fmt.Sprintf("  %s[%s]%s", colorGray, e.Profile, colorReset)
			}
			fmt.Fprintf(out, "    %-40s %s%-12s%s%s%s\n",
				name,
				colorGray, e.Version, colorReset,
				id, profile)
		}
	}
	fmt.Fprintln(out)
}

// PrintInventorySummary prints a compact count-per-ecosystem summary.
func PrintInventorySummary(out io.Writer, inv *models.Inventory) {
	pkgCounts := make(map[models.Ecosystem]int)
	for _, p := range inv.Packages {
		pkgCounts[p.Ecosystem]++
	}
	extCounts := make(map[models.Ecosystem]int)
	for _, e := range inv.Extensions {
		extCounts[e.Ecosystem]++
	}

	fmt.Fprintf(out, "\n%sPACKAGES%s  %d total\n", colorBold, colorReset, len(inv.Packages))
	pkgEcos := []models.Ecosystem{models.EcoNpm, models.EcoPip, models.EcoCargo, models.EcoGo, models.EcoBrew}
	for _, eco := range pkgEcos {
		if n := pkgCounts[eco]; n > 0 {
			fmt.Fprintf(out, "  %-12s %s%d%s\n", eco, colorCyan, n, colorReset)
		}
	}

	fmt.Fprintf(out, "\n%sEXTENSIONS%s  %d total\n", colorBold, colorReset, len(inv.Extensions))
	extEcos := []models.Ecosystem{
		models.EcoVSCode, models.EcoCursor, models.EcoWindsurf, models.EcoZed,
		models.EcoJetBrains, models.EcoChrome, models.EcoEdge, models.EcoBrave,
	}
	for _, eco := range extEcos {
		if n := extCounts[eco]; n > 0 {
			fmt.Fprintf(out, "  %-12s %s%d%s\n", eco, colorCyan, n, colorReset)
		}
	}

	fmt.Fprintf(out, "\n%sAI AGENTS%s\n", colorBold, colorReset)
	if n := extCounts[models.EcoMCP]; n > 0 {
		fmt.Fprintf(out, "  %-12s %s%d%s\n", "mcp servers", colorCyan, n, colorReset)
	} else {
		fmt.Fprintf(out, "  %snone found%s\n", colorGray, colorReset)
	}
	fmt.Fprintln(out)
}

func shortenPath(p string) string {
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}
