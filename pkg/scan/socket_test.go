package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zainguard/chainwatch/pkg/models"
)

// capturingTransport records the last request body and serves a canned response.
type capturingTransport struct {
	lastBody []byte
	response string
	status   int
}

func (t *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		t.lastBody, _ = io.ReadAll(req.Body)
	}
	status := t.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(t.response)),
		Header:     make(http.Header),
	}, nil
}

func newTestSocket(ndjson string) (*SocketClient, *capturingTransport) {
	tr := &capturingTransport{response: ndjson}
	c := NewSocketClient("test-key")
	c.client = &http.Client{Transport: tr}
	return c, tr
}

// --- PURL construction ---

func TestSocketPURL_Npm(t *testing.T) {
	c, tr := newTestSocket("")
	pkgs := []models.PackageRecord{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm},
	}
	_, _ = c.Scan(context.Background(), pkgs, nil)

	var req socketPurlReq
	if err := json.Unmarshal(tr.lastBody, &req); err != nil {
		t.Fatalf("could not parse request body: %v", err)
	}
	if len(req.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(req.Components))
	}
	want := "pkg:npm/lodash@4.17.21"
	if req.Components[0].PURL != want {
		t.Errorf("npm PURL: got %q, want %q", req.Components[0].PURL, want)
	}
}

func TestSocketPURL_ScopedNpm(t *testing.T) {
	c, tr := newTestSocket("")
	pkgs := []models.PackageRecord{
		{Name: "@scope/pkg", Version: "1.0.0", Ecosystem: models.EcoNpm},
	}
	_, _ = c.Scan(context.Background(), pkgs, nil)

	var req socketPurlReq
	if err := json.Unmarshal(tr.lastBody, &req); err != nil {
		t.Fatalf("could not parse request body: %v", err)
	}
	// url.PathEscape encodes @ and / in the scoped name
	if !strings.HasPrefix(req.Components[0].PURL, "pkg:npm/") {
		t.Errorf("scoped npm PURL should start with pkg:npm/, got %q", req.Components[0].PURL)
	}
	if !strings.HasSuffix(req.Components[0].PURL, "@1.0.0") {
		t.Errorf("scoped npm PURL should end with @1.0.0, got %q", req.Components[0].PURL)
	}
}

func TestSocketPURL_VSCode(t *testing.T) {
	c, tr := newTestSocket("")
	exts := []models.ExtensionRecord{
		{Publisher: "ms-python", Name: "python", Version: "2024.0.1", Ecosystem: models.EcoVSCode},
	}
	_, _ = c.Scan(context.Background(), nil, exts)

	var req socketPurlReq
	if err := json.Unmarshal(tr.lastBody, &req); err != nil {
		t.Fatalf("could not parse request body: %v", err)
	}
	want := "pkg:vscode/ms-python/python@2024.0.1"
	if req.Components[0].PURL != want {
		t.Errorf("vscode PURL: got %q, want %q", req.Components[0].PURL, want)
	}
}

func TestSocketPURL_Chrome(t *testing.T) {
	c, tr := newTestSocket("")
	exts := []models.ExtensionRecord{
		{ID: "pmilcmjbofinpnbnpanpdadijibcgifc", Version: "unknown", Ecosystem: models.EcoChrome},
	}
	_, _ = c.Scan(context.Background(), nil, exts)

	var req socketPurlReq
	if err := json.Unmarshal(tr.lastBody, &req); err != nil {
		t.Fatalf("could not parse request body: %v", err)
	}
	// Chrome PURLs have no version
	want := "pkg:chrome/pmilcmjbofinpnbnpanpdadijibcgifc"
	if req.Components[0].PURL != want {
		t.Errorf("chrome PURL: got %q, want %q", req.Components[0].PURL, want)
	}
}

// VS Code extensions without Publisher+Name are skipped.
func TestSocketScan_SkipsVSCodeWithoutPublisher(t *testing.T) {
	c, tr := newTestSocket("")
	exts := []models.ExtensionRecord{
		{ID: "some-id", Name: "", Publisher: "", Version: "1.0.0", Ecosystem: models.EcoVSCode},
	}
	_, _ = c.Scan(context.Background(), nil, exts)

	// No request should have been made (nothing to scan).
	if tr.lastBody != nil {
		t.Error("expected no request for VS Code extension missing publisher+name")
	}
}

// Chrome extensions without an ID are skipped.
func TestSocketScan_SkipsChromeWithoutID(t *testing.T) {
	c, tr := newTestSocket("")
	exts := []models.ExtensionRecord{
		{ID: "", Name: "some-ext", Version: "1.0.0", Ecosystem: models.EcoChrome},
	}
	_, _ = c.Scan(context.Background(), nil, exts)
	if tr.lastBody != nil {
		t.Error("expected no request for Chrome extension missing ID")
	}
}

// --- NDJSON parsing and finding extraction ---

func TestSocketScan_NpmFinding(t *testing.T) {
	ndjson := `{"name":"lodash","version":"4.17.21","type":"npm","alerts":[{"type":"obfuscatedFiles","severity":"high","category":"supplyChainRisk","props":{"notes":"Obfuscation detected"}}]}` + "\n"

	c, _ := newTestSocket(ndjson)
	pkgs := []models.PackageRecord{{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm}}
	findings, err := c.Scan(context.Background(), pkgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ThreatType != models.ThreatObfuscated {
		t.Errorf("threat type: got %q, want %q", f.ThreatType, models.ThreatObfuscated)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q, want %q", f.Severity, models.SeverityHigh)
	}
	if f.Description != "Obfuscation detected" {
		t.Errorf("description: got %q", f.Description)
	}
	if f.Ecosystem != models.EcoNpm {
		t.Errorf("ecosystem: got %q, want npm", f.Ecosystem)
	}
}

func TestSocketScan_VSCodeFinding(t *testing.T) {
	ndjson := `{"name":"ms-python.python","version":"2024.0.1","type":"vscode","alerts":[{"type":"malware","severity":"critical","category":"supplyChainRisk","props":{"notes":"Malicious payload detected"}}]}` + "\n"

	c, _ := newTestSocket(ndjson)
	exts := []models.ExtensionRecord{
		{Publisher: "ms-python", Name: "python", Version: "2024.0.1", Ecosystem: models.EcoVSCode},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ThreatType != models.ThreatMalware {
		t.Errorf("threat type: got %q, want malware", findings[0].ThreatType)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("severity: got %q, want critical", findings[0].Severity)
	}
}

func TestSocketScan_ChromeFinding_NoteField(t *testing.T) {
	// Chrome extensions use "note" (singular) not "notes"
	ndjson := `{"name":"pmilcmjbofinpnbnpanpdadijibcgifc","version":"3.0.0","type":"chrome","alerts":[{"type":"extensionMalware","severity":"critical","category":"supplyChainRisk","props":{"note":"Confirmed malicious extension"}}]}` + "\n"

	c, _ := newTestSocket(ndjson)
	exts := []models.ExtensionRecord{
		{ID: "pmilcmjbofinpnbnpanpdadijibcgifc", Version: "unknown", Ecosystem: models.EcoChrome},
	}
	findings, err := c.Scan(context.Background(), nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Description != "Confirmed malicious extension" {
		t.Errorf("description (from 'note'): got %q", findings[0].Description)
	}
	// Chrome finding uses Socket's resolved version when ext.Version is unknown
	if findings[0].Version != "3.0.0" {
		t.Errorf("version: expected Socket's resolved version 3.0.0, got %q", findings[0].Version)
	}
}

// --- Category filtering ---

func TestSocketScan_SkipsVulnerabilityCategory(t *testing.T) {
	ndjson := `{"name":"lodash","version":"4.17.21","type":"npm","alerts":[` +
		`{"type":"CVE-2021-1234","severity":"critical","category":"vulnerability","props":{}},` +
		`{"type":"obfuscatedFiles","severity":"high","category":"supplyChainRisk","props":{"notes":"Obfuscated"}}` +
		`]}` + "\n"

	c, _ := newTestSocket(ndjson)
	pkgs := []models.PackageRecord{{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm}}
	findings, err := c.Scan(context.Background(), pkgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Only the supplyChainRisk alert should appear, not the vulnerability
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (CVE filtered out), got %d", len(findings))
	}
	if findings[0].ThreatType != models.ThreatObfuscated {
		t.Errorf("expected obfuscated-code finding, got %q", findings[0].ThreatType)
	}
}

func TestSocketScan_SkipsLicenseCategory(t *testing.T) {
	ndjson := `{"name":"express","version":"4.18.0","type":"npm","alerts":[{"type":"licenseIssue","severity":"high","category":"license","props":{}}]}` + "\n"

	c, _ := newTestSocket(ndjson)
	pkgs := []models.PackageRecord{{Name: "express", Version: "4.18.0", Ecosystem: models.EcoNpm}}
	findings, err := c.Scan(context.Background(), pkgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (license filtered out), got %d", len(findings))
	}
}

// --- Severity mapping ---

func TestSocketSeverityMap(t *testing.T) {
	cases := []struct {
		apiSev  string
		want    models.Severity
	}{
		{"critical", models.SeverityCritical},
		{"high", models.SeverityHigh},
		{"middle", models.SeverityMedium}, // Socket uses "middle" for medium
		{"medium", models.SeverityMedium},
		{"low", models.SeverityLow},
	}
	for _, tc := range cases {
		got := socketSeverityMap[tc.apiSev]
		if got != tc.want {
			t.Errorf("severityMap[%q] = %q, want %q", tc.apiSev, got, tc.want)
		}
	}
}

// --- Auth error handling ---

func TestSocketScan_AuthError(t *testing.T) {
	tr := &capturingTransport{response: `{"error":"unauthorized"}`, status: http.StatusUnauthorized}
	c := NewSocketClient("bad-key")
	c.client = &http.Client{Transport: tr}

	pkgs := []models.PackageRecord{{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcoNpm}}
	_, err := c.Scan(context.Background(), pkgs, nil)
	if err == nil {
		t.Error("expected error for 401 response, got nil")
	}
}

// --- Empty API key skips scan ---

func TestSocketScan_NoApiKey_SkipsNonNpm(t *testing.T) {
	// An empty key is allowed — the client still runs but hits the unauthenticated rate limit
	// What matters is it doesn't panic.
	c := NewSocketClient("")
	// No packages or extensions → should return nil without any request
	findings, err := c.Scan(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if findings != nil {
		t.Error("expected nil findings for empty inventory")
	}
}

// --- Unknown alert type is dropped ---

func TestSocketScan_UnknownAlertType_Dropped(t *testing.T) {
	ndjson := `{"name":"pkg","version":"1.0.0","type":"npm","alerts":[{"type":"unknownFutureAlert","severity":"high","category":"supplyChainRisk","props":{}}]}` + "\n"

	c, _ := newTestSocket(ndjson)
	pkgs := []models.PackageRecord{{Name: "pkg", Version: "1.0.0", Ecosystem: models.EcoNpm}}
	findings, err := c.Scan(context.Background(), pkgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unknown alert type, got %d", len(findings))
	}
}

// --- Multiple alerts in one response ---

func TestSocketScan_MultipleAlerts(t *testing.T) {
	ndjson := `{"name":"evil-pkg","version":"2.0.0","type":"npm","alerts":[` +
		`{"type":"malware","severity":"critical","category":"supplyChainRisk","props":{"notes":"Credential stealer"}},` +
		`{"type":"networkAccess","severity":"high","category":"supplyChainRisk","props":{"notes":"Connects to remote server"}}` +
		`]}` + "\n"

	c, _ := newTestSocket(ndjson)
	pkgs := []models.PackageRecord{{Name: "evil-pkg", Version: "2.0.0", Ecosystem: models.EcoNpm}}
	findings, err := c.Scan(context.Background(), pkgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}
