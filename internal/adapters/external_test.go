package adapters

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

func testExternalInput() AdapterInput {
	session := models.Session{
		ID:          "session-1",
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com/search?q=test",
		CreatedAt:   time.Now().UTC(),
	}
	return AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target: models.Target{
			ID:        "target-1",
			SessionID: session.ID,
			Host:      "example.com",
			Port:      443,
			Protocol:  "https",
			IsAlive:   true,
		},
	}
}

type fakeScope struct {
	allowed map[string]bool
}

func (s fakeScope) IsInScope(raw string) (bool, string) {
	if s.allowed[raw] {
		return true, ""
	}
	return false, "out of scope"
}

func TestParseNmapFindings(t *testing.T) {
	raw := `<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="closed"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port><port protocol="tcp" portid="8443"><state state="open"/></port></ports></host></nmaprun>`
	findings := parseNmapFindings(testExternalInput(), raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ToolID != "nmap" || findings[0].Type != models.FindingTypeExposure || findings[0].Severity != models.SeverityInfo {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].EvidenceRaw == "" || findings[0].EvidenceNormalized == "" {
		t.Fatal("expected raw and normalized evidence")
	}
	if !testHasTag(findings[1].Tags, "unknown") {
		t.Fatalf("expected unknown service tag for service-less open port, got %#v", findings[1].Tags)
	}
}

func TestParseFFUFFindings(t *testing.T) {
	raw := `{"results":[{"url":"https://example.com/admin","status":200,"length":42,"words":4,"lines":1},{"url":"https://example.com/missing","status":404,"length":9},{"url":"https://example.com/login","status":302,"redirectlocation":"https://example.com/auth"}]}`
	findings := parseFFUFFindings(testExternalInput(), raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ToolID != "ffuf" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[1].Severity != models.SeverityInfo || findings[1].EvidenceNormalized == "" {
		t.Fatalf("expected non-admin redirect discovery with normalized evidence, got %#v", findings[1])
	}
}

func TestParseSQLMapFindings(t *testing.T) {
	raw := `Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
q parameter is vulnerable.`
	findings := parseSQLMapFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "sqlmap" || findings[0].Parameter != "q" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseSQLMapFindingsIgnoresNegativeOutput(t *testing.T) {
	raw := `all tested parameters do not appear to be injectable`
	findings := parseSQLMapFindings(testExternalInput(), raw)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for negative sqlmap output, got %d", len(findings))
	}
}

func TestParseDalfoxFindings(t *testing.T) {
	raw := `[{"type":"reflected","param":"q","payload":"<script>alert(1)</script>","poc":"https://example.com/search?q=%3Cscript%3E"}]`
	findings := parseDalfoxFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "dalfox" || findings[0].Parameter != "q" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseDalfoxTextFindings(t *testing.T) {
	findings := parseDalfoxTextFindings(testExternalInput(), "Verified XSS vulnerability on parameter q")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "dalfox" || findings[0].Parameter != "q" || findings[0].EvidenceRaw == "" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseHostLines(t *testing.T) {
	raw := "Example.com\nhttps://api.example.com/login\n*.WWW.example.com\n"
	targets := parseHostLines(testExternalInput(), "subfinder", raw, "https", 443)
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0].Host != "example.com" || targets[1].Host != "api.example.com" || targets[2].Host != "www.example.com" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	for _, target := range targets {
		if target.Protocol != "https" || target.Port != 443 || target.DiscoveredBy != "subfinder" {
			t.Fatalf("target was not normalized: %#v", target)
		}
	}
}

func TestParseNaabuTargetsAndFindings(t *testing.T) {
	raw := "example.com:80\nexample.com:443\n"
	targets := parseNaabuTargets(testExternalInput(), raw)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Protocol != "http" || targets[1].Protocol != "https" {
		t.Fatalf("unexpected protocols: %#v", targets)
	}
	findings := parseNaabuFindings(testExternalInput(), raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ToolID != "naabu" || findings[0].Severity != models.SeverityInfo {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseHTTPXOutput(t *testing.T) {
	raw := `{"url":"https://example.com","host":"example.com","scheme":"https","port":"443","status_code":200,"title":"Home","tech":["nginx","React"]}`
	targets, technologies, findings := parseHTTPXOutput(testExternalInput(), raw)
	if len(targets) != 1 || len(technologies) != 2 || len(findings) != 1 {
		t.Fatalf("unexpected parsed counts: targets=%d technologies=%d findings=%d", len(targets), len(technologies), len(findings))
	}
	if targets[0].Host != "example.com" || !targets[0].IsAlive {
		t.Fatalf("unexpected target: %#v", targets[0])
	}
	if technologies[0].TargetID != targets[0].ID || technologies[0].SourceTool != "httpx" {
		t.Fatalf("technology was not linked to target: %#v", technologies[0])
	}
	if findings[0].ToolID != "httpx" || findings[0].Title != "Live HTTP service discovered" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseWhoisFindings(t *testing.T) {
	raw := "Registrar: Example Registrar\nOrgName: Example Org\nCountry: US\n"
	findings := parseWhoisFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "whois" || findings[0].EvidenceRaw == "" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseURLLineFindings(t *testing.T) {
	raw := "https://example.com/login\nhttps://example.com/login\nhttps://example.com/admin\n"
	findings := parseURLLineFindings(testExternalInput(), "waybackurls", raw, "Archived URL discovered", []string{"wayback", "url"})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ToolID != "waybackurls" || findings[0].Title != "Archived URL discovered" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseCrtSHTargets(t *testing.T) {
	rows := []struct {
		NameValue string `json:"name_value"`
	}{
		{NameValue: "*.www.example.com\napi.example.com"},
		{NameValue: "api.example.com"},
	}
	targets := parseCrtSHTargets(testExternalInput(), rows)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].DiscoveredBy != "crtsh" || targets[1].Host != "api.example.com" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestScopedRootDomainDoesNotBroadenSubdomainScope(t *testing.T) {
	input := testExternalInput()
	input.Target.Host = "api.example.com"
	input.Scope = fakeScope{allowed: map[string]bool{"api.example.com": true}}
	if got := scopedRootDomain(input); got != "api.example.com" {
		t.Fatalf("expected scoped subdomain, got %q", got)
	}

	input.Scope = fakeScope{allowed: map[string]bool{"example.com": true}}
	if got := scopedRootDomain(input); got != "example.com" {
		t.Fatalf("expected scoped root domain, got %q", got)
	}
}

func TestParseWhatWebOutput(t *testing.T) {
	raw := `[{"target":"https://example.com","plugins":{"nginx":{"version":["1.25.1"]},"React":{}}}]`
	technologies, findings := parseWhatWebOutput(testExternalInput(), raw)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if len(technologies) != 2 {
		t.Fatalf("expected 2 technologies, got %d", len(technologies))
	}
	var nginx models.Technology
	for _, technology := range technologies {
		if technology.Name == "nginx" {
			nginx = technology
		}
	}
	if nginx.Version != "1.25.1" || nginx.SourceTool != "whatweb" {
		t.Fatalf("unexpected nginx technology: %#v", nginx)
	}
}

func TestParseNucleiTechOutput(t *testing.T) {
	raw := `{"template-id":"tech-detect:nginx","matched-at":"https://example.com","info":{"name":"nginx technology detected","severity":"info"}}`
	technologies, findings := parseNucleiTechOutput(testExternalInput(), raw)
	if len(technologies) != 1 || len(findings) != 1 {
		t.Fatalf("unexpected parsed counts: technologies=%d findings=%d", len(technologies), len(findings))
	}
	if technologies[0].SourceTool != "nuclei-tech" || findings[0].ToolID != "nuclei-tech" {
		t.Fatalf("unexpected parsed output: %#v %#v", technologies[0], findings[0])
	}
}

func TestParseTestSSLOutput(t *testing.T) {
	raw := `[{"id":"TLS1_0","severity":"LOW","finding":"TLS 1.0 offered"},{"id":"cert","severity":"OK","finding":"certificate valid"}]`
	findings := parseTestSSLOutput(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "testssl" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseGraphQLIntrospection(t *testing.T) {
	findings := parseGraphQLIntrospection(testExternalInput(), "https://example.com/graphql", 200, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "graphql-introspection" || findings[0].Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseOpenAPIDocument(t *testing.T) {
	findings := parseOpenAPIDocument(testExternalInput(), "https://example.com/openapi.json", 200, `{"openapi":"3.0.3","paths":{}}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "openapi-discovery" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseWPScanOutput(t *testing.T) {
	raw := `{"version":{"number":"6.4.2"},"main_theme":{"slug":"twentytwentyfour","version":{"number":"1.0"}},"plugins":{"akismet":{"version":{"number":"5.3"}}}}`
	technologies, findings := parseWPScanOutput(testExternalInput(), raw)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if len(technologies) != 3 {
		t.Fatalf("expected 3 technologies, got %d", len(technologies))
	}
	if technologies[0].Name != "WordPress" || technologies[0].Version != "6.4.2" {
		t.Fatalf("unexpected WordPress technology: %#v", technologies[0])
	}
}

func TestParseDroopescanOutput(t *testing.T) {
	raw := `{"identified":"drupal","version":["10.2.0"]}`
	technologies, findings := parseDroopescanOutput(testExternalInput(), raw)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if len(technologies) != 1 {
		t.Fatalf("expected 1 technology, got %d", len(technologies))
	}
	if technologies[0].Name != "drupal" || technologies[0].Version != "10.2.0" || technologies[0].SourceTool != "droopescan" {
		t.Fatalf("unexpected technology: %#v", technologies[0])
	}
}

func TestParseArjunFindings(t *testing.T) {
	raw := `{"https://example.com/":{"params":["debug","next"]}}`
	findings := parseArjunFindings(testExternalInput(), raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	seen := map[string]bool{}
	for _, finding := range findings {
		if finding.ToolID != "arjun" || finding.Parameter == "" {
			t.Fatalf("unexpected finding: %#v", finding)
		}
		seen[finding.Parameter] = true
	}
	if !seen["debug"] || !seen["next"] {
		t.Fatalf("expected debug and next params, got %#v", seen)
	}
}

func TestParseEndpointFindings(t *testing.T) {
	raw := `/api/v1/users
https://example.com/static/app.js
https://other.example.net/out-of-scope`
	input := testExternalInput()
	input.Scope = fakeScope{allowed: map[string]bool{"example.com": true}}
	findings := parseEndpointFindings(input, "linkfinder", raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].ToolID != "linkfinder" || findings[0].Tags[1] != "javascript-endpoint" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseGitleaksFindings(t *testing.T) {
	raw := `[{"RuleID":"generic-api-key","Description":"Generic API key","Secret":"abc123456789012345"}]`
	findings := parseGitleaksFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "gitleaks" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestScanSecretFindings(t *testing.T) {
	raw := `const aws = "AKIA1234567890ABCDEF";`
	findings := scanSecretFindings(testExternalInput(), "js-secret-scan", "https://example.com/app.js", raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "js-secret-scan" || findings[0].URL != "https://example.com/app.js" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseCORSFindings(t *testing.T) {
	headers := map[string]string{
		"access-control-allow-origin":      "*",
		"access-control-allow-credentials": "true",
	}
	findings := parseCORSFindings(testExternalInput(), "https://example.com/", "https://nyx.invalid", headers, `{"access-control-allow-origin":"*"}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "cors-check" || findings[0].Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if !testHasTag(findings[0].Tags, "cors-wildcard-credentials") {
		t.Fatalf("expected cors-wildcard-credentials tag, got %#v", findings[0].Tags)
	}
}

func TestParseCORSFindingsReflectedOriginWithoutCredentials(t *testing.T) {
	headers := map[string]string{
		"access-control-allow-origin": "https://nyx.invalid",
	}
	findings := parseCORSFindings(testExternalInput(), "https://example.com/", "https://nyx.invalid", headers, `{"access-control-allow-origin":"https://nyx.invalid"}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "cors-check" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if !testHasTag(findings[0].Tags, "cors-missing-vary-origin") {
		t.Fatalf("expected missing vary tag, got %#v", findings[0].Tags)
	}
}

func TestParseCloudBucketFindings(t *testing.T) {
	raw := `<ListBucketResult><Name>example</Name><Contents><Key>public.txt</Key></Contents></ListBucketResult>`
	findings := parseCloudBucketFindings(testExternalInput(), "https://example.s3.amazonaws.com/", 200, raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "cloud-bucket-check" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestVulnerabilityTargetURLUsesHiddenParameter(t *testing.T) {
	input := testExternalInput()
	input.Session.TargetInput = "https://example.com/"
	input.PriorFindings = []models.Finding{{
		ToolID:    "arjun",
		Parameter: "debug",
		Tags:      []string{"arjun", "hidden-parameter"},
	}}
	got := vulnerabilityTargetURL(input)
	if got != "https://example.com/?debug=nyx" {
		t.Fatalf("unexpected vulnerability target URL: %s", got)
	}
}

func TestParseNucleiVulnFindings(t *testing.T) {
	raw := `{"template-id":"cves/2024/test","matched-at":"https://example.com","info":{"name":"Example CVE","severity":"high"}}`
	findings := parseNucleiVulnFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "nuclei-vuln" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseSSRFMapFindings(t *testing.T) {
	findings := parseSSRFMapFindings(testExternalInput(), "Parameter url appears vulnerable to SSRF")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "ssrfmap" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseJWTToolFindings(t *testing.T) {
	input := testExternalInput()
	input.Session.TargetInput = "https://example.com/?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
	findings := parseJWTToolFindings(input, "Token appears vulnerable to alg:none")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "jwt-tool" || findings[0].Severity != models.SeverityCritical {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseOAuthFindings(t *testing.T) {
	findings := parseOAuthFindings(testExternalInput(), "https://example.com/oauth?redirect_uri=https://nyx.invalid/callback", 302, "https://nyx.invalid/callback", "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "oauth-check" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestReflectedXSSCheckUsesSeededRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("search=" + r.URL.Query().Get("q")))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/search?q=seed")
	adapter := NewReflectedXSSCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected reflected XSS check to run with seeded query route")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "reflected-xss-check" || finding.Parameter != "q" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestReflectedXSSCheckDoesNotReportWithoutReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("constant body"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/search?q=seed")
	out, err := NewReflectedXSSCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestReflectedXSSCheckDoesNotReportEscapedReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(html.EscapeString(r.URL.Query().Get("q"))))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/search?q=seed")
	out, err := NewReflectedXSSCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings for escaped reflection, got %#v", out.Findings)
	}
}

func TestBruteForceCheckConfirmsConfiguredCredential(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") == "admin" && r.URL.Query().Get("password") == "password" {
			attempts++
			_, _ = w.Write([]byte("Welcome to the password protected area admin"))
			return
		}
		_, _ = w.Write([]byte(`<form method="get" action="/brute"><input name="username"><input name="password" type="password"><button name="Login" value="Login">Login</button></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/brute")
	input.Session.ToolParameters[models.SessionScanOptionsKey]["safe_active_checks"] = map[string]any{
		"allow_credential_validation": true,
		"intentionally_vulnerable":    true,
		"non_production":              true,
		"credential_max_attempts":     1,
		"credential_candidates": []any{
			map[string]any{"username": "admin", "password": "password"},
		},
		"credential_success_contains": []any{"Welcome to the password protected area"},
	}
	adapter := NewBruteForceCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected brute-force check to run with seeded credential route")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly one credential attempt, got %d; stdout=%s", attempts, out.ToolRun.RawStdout)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "brute-force-check" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh || finding.Parameter != "username,password" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if strings.Contains(out.ToolRun.RawStdout, "password") || strings.Contains(finding.EvidenceRaw, "password") {
		t.Fatalf("expected password to be redacted from evidence/stdout, stdout=%s evidence=%s", out.ToolRun.RawStdout, finding.EvidenceRaw)
	}
}

func TestBruteForceCheckRequiresBenchmarkSafetyGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="post" action="/login"><input name="username"><input name="password"></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/login")
	out, err := NewBruteForceCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
	if !strings.Contains(out.ToolRun.RawStdout, "active_credential_validation_requires") {
		t.Fatalf("expected safety skip reason, got %s", out.ToolRun.RawStdout)
	}
}

func TestBruteForceCheckStopsOnLockout(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			attempts++
			w.WriteHeader(http.StatusLocked)
			_, _ = w.Write([]byte("locked"))
			return
		}
		_, _ = w.Write([]byte(`<form method="post" action="/login"><input name="username"><input name="password"></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/login")
	input.Session.ToolParameters[models.SessionScanOptionsKey]["safe_active_checks"] = map[string]any{
		"allow_credential_validation": true,
		"intentionally_vulnerable":    true,
		"non_production":              true,
		"credential_max_attempts":     3,
		"credential_candidates": []any{
			map[string]any{"username": "admin", "password": "one"},
			map[string]any{"username": "admin", "password": "two"},
		},
	}
	out, err := NewBruteForceCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("expected lockout to stop after one attempt, got %d", attempts)
	}
	if len(out.Findings) != 0 || !strings.Contains(out.ToolRun.RawStdout, "lockout=true") {
		t.Fatalf("expected lockout without findings, findings=%#v stdout=%s", out.Findings, out.ToolRun.RawStdout)
	}
}

func TestBruteForceCandidatesUseDVWASeededRoutes(t *testing.T) {
	input := testHTTPAdapterInput(t, "http://example.test",
		"/vulnerabilities/brute/",
		"/vulnerabilities/xss_s/",
	)
	candidates := bruteForceCandidateURLs(input, 10)
	if len(candidates) != 1 || candidates[0] != "http://example.test/vulnerabilities/brute/" {
		t.Fatalf("expected seeded DVWA brute force candidate, got %#v", candidates)
	}
}

func TestStoredXSSCheckConfirmsReadbackMarker(t *testing.T) {
	var stored []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			stored = append(stored, r.Form.Get("message"))
			_, _ = w.Write([]byte("saved"))
		default:
			_, _ = w.Write([]byte(`<form method="post" action="/guestbook"><input name="name"><textarea name="message"></textarea><button name="submit" value="Sign">Sign</button></form>`))
			for _, value := range stored {
				_, _ = w.Write([]byte(value))
			}
		}
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/guestbook")
	input.ToolParameters = map[string]any{
		"allow_stored_xss":         true,
		"intentionally_vulnerable": true,
		"non_production":           true,
	}
	adapter := NewStoredXSSCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected stored XSS check to run with seeded stored route")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "stored-xss-check" || finding.Parameter != "message" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestStoredXSSCheckRequiresBenchmarkSafetyGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="post" action="/guestbook"><textarea name="message"></textarea></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/guestbook")
	out, err := NewStoredXSSCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
	if !strings.Contains(out.ToolRun.RawStdout, "active_stored_xss_requires") {
		t.Fatalf("expected safety skip reason, got %s", out.ToolRun.RawStdout)
	}
}

func TestStoredXSSCheckDoesNotReportEscapedReadback(t *testing.T) {
	var stored []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			stored = append(stored, r.Form.Get("message"))
			_, _ = w.Write([]byte("saved"))
		default:
			_, _ = w.Write([]byte(`<form method="post" action="/guestbook"><textarea name="message"></textarea></form>`))
			for _, value := range stored {
				_, _ = w.Write([]byte(html.EscapeString(value)))
			}
		}
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/guestbook")
	input.ToolParameters = map[string]any{
		"allow_stored_xss":         true,
		"intentionally_vulnerable": true,
		"non_production":           true,
	}
	out, err := NewStoredXSSCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings for escaped readback, got %#v", out.Findings)
	}
}

func TestStoredXSSCandidatesUseDVWASeededRoutes(t *testing.T) {
	input := testHTTPAdapterInput(t, "http://example.test",
		"/vulnerabilities/xss_s/",
		"/vulnerabilities/xss_r/?name=nyx",
	)
	candidates := storedXSSCandidateURLs(input, 10)
	if len(candidates) != 1 || candidates[0] != "http://example.test/vulnerabilities/xss_s/" {
		t.Fatalf("expected seeded DVWA stored XSS candidate, got %#v", candidates)
	}
}

func TestQueryMutationCandidatesUsesDVWASeededRoutes(t *testing.T) {
	input := testHTTPAdapterInput(t, "http://example.test",
		"/vulnerabilities/sqli/?id=1&Submit=Submit",
		"/vulnerabilities/xss_r/?name=nyx",
	)
	candidates := queryMutationCandidates(input, 10)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		seen[candidate.RawURL+"#"+candidate.Parameter] = true
	}
	if !seen["http://example.test/vulnerabilities/sqli/?id=1&Submit=Submit#id"] {
		t.Fatalf("expected seeded DVWA SQLi id parameter candidate, got %#v", candidates)
	}
	if !seen["http://example.test/vulnerabilities/xss_r/?name=nyx#name"] {
		t.Fatalf("expected seeded DVWA reflected XSS name parameter candidate, got %#v", candidates)
	}
}

func TestOpenRedirectCheckUsesSeededRoutesWithoutFollowingRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/redirect?next=/home")
	adapter := NewOpenRedirectCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected open redirect check to run with redirect-like parameter")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "open-redirect-check" || finding.Parameter != "next" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestOpenRedirectCheckIgnoresNonRedirectParameters(t *testing.T) {
	input := testHTTPAdapterInput(t, "http://example.test", "/search?q=seed")
	if NewOpenRedirectCheck().ShouldRun(input) {
		t.Fatal("expected open redirect check to skip non-redirect parameters")
	}
}

func TestSQLICheckConfirmsBooleanDifferential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch {
		case strings.Contains(id, "1=2"):
			_, _ = w.Write([]byte("no rows"))
		case id == "1" || strings.Contains(id, "1=1"):
			_, _ = w.Write([]byte("user: alice"))
		default:
			_, _ = w.Write([]byte("no rows"))
		}
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/item?id=1")
	adapter := NewSQLICheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected SQLi check to run with seeded query route")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "sqli-check" || finding.Parameter != "id" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestSQLICheckConfirmsQuotedBooleanDifferentialForNumericSeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		_, _ = w.Write([]byte("ID: " + html.EscapeString(id) + "\n"))
		switch {
		case strings.Contains(id, "' AND '1'='2"):
			_, _ = w.Write([]byte("no rows"))
		case strings.Contains(id, "' AND '1'='1"):
			_, _ = w.Write([]byte("user: alice"))
		case id == "1":
			_, _ = w.Write([]byte("user: alice"))
		default:
			_, _ = w.Write([]byte("no rows"))
		}
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/item?id=1")
	out, err := NewSQLICheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "sqli-check" || finding.Parameter != "id" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if !strings.Contains(out.ToolRun.RawStdout, "technique=quoted-boolean-differential boolean=true") {
		t.Fatalf("expected quoted boolean evidence in stdout, got %s", out.ToolRun.RawStdout)
	}
}

func TestSQLICheckReportsSQLErrorAsSuspected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			_, _ = w.Write([]byte("You have an error in your SQL syntax near \"'\""))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/item?id=1")
	out, err := NewSQLICheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "sqli-check" || finding.Parameter != "id" || finding.Status != "suspected" || finding.Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestSQLICheckDoesNotReportStableLiteralHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("literal:" + r.URL.Query().Get("id")))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/item?id=1")
	out, err := NewSQLICheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestFileInclusionCheckConfirmsHostsFileInclusion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch {
		case strings.Contains(page, "etc/hosts"):
			_, _ = w.Write([]byte("127.0.0.1 localhost\n::1 localhost ip6-localhost\n"))
		default:
			_, _ = w.Write([]byte("normal include"))
		}
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/view?page=include.php")
	adapter := NewFileInclusionCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected file inclusion check to run with seeded page parameter")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "file-inclusion-check" || finding.Parameter != "page" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if !strings.Contains(strings.ToLower(finding.Title), "file inclusion") {
		t.Fatalf("expected file inclusion title, got %q", finding.Title)
	}
}

func TestFileInclusionCheckIgnoresStableLiteralHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("normal include"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/view?page=include.php")
	out, err := NewFileInclusionCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestCommandInjectionCheckConfirmsBenchmarkSafeMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post" action="/exec"><input name="ip"><input type="submit" name="Submit" value="Submit"></form>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		value := r.Form.Get("ip")
		fields := strings.Fields(value)
		if strings.Contains(value, "echo ") && len(fields) > 0 {
			_, _ = w.Write([]byte("ping output\n" + fields[len(fields)-1] + "\n"))
			return
		}
		_, _ = w.Write([]byte("ping output"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/exec")
	input.Session.ToolParameters[models.SessionScanOptionsKey]["auth_profile"] = map[string]any{
		"safe_active_checks": map[string]any{
			"allow_command_injection":  true,
			"intentionally_vulnerable": true,
			"non_production":           true,
		},
	}
	adapter := NewCommandInjectionCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected command injection check to run with exec seed")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "command-injection-check" || finding.Parameter != "ip" || finding.Method != http.MethodPost || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestCommandInjectionCheckRequiresBenchmarkSafetyGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="post" action="/exec"><input name="ip"></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/exec")
	out, err := NewCommandInjectionCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
	if !strings.Contains(out.ToolRun.RawStdout, "active_command_injection_requires") {
		t.Fatalf("expected safety skip reason, got %s", out.ToolRun.RawStdout)
	}
}

func TestCommandInjectionCheckIgnoresReflectedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post" action="/exec"><input name="command"></form>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(html.EscapeString(r.Form.Get("command"))))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/exec")
	input.ToolParameters = map[string]any{
		"allow_command_injection":  true,
		"intentionally_vulnerable": true,
		"non_production":           true,
	}
	out, err := NewCommandInjectionCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestUploadCheckConfirmsMarkerUpload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post" enctype="multipart/form-data"><input type="file" name="avatar"></form>`))
			return
		}
		_ = r.ParseMultipartForm(1 << 20)
		file, _, err := r.FormFile("avatar")
		if err != nil {
			t.Errorf("expected avatar upload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		body, _ := io.ReadAll(file)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/upload")
	adapter := NewUploadCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected upload check to run with upload seed")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "upload-check" || finding.Parameter != "avatar" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestIDORCheckReportsAdjacentObjectAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		_, _ = w.Write([]byte(`{"id":"` + id + `","owner":"user-` + id + `"}`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/api/basket?id=1")
	adapter := NewIDORCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected IDOR check to run with object id seed")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "idor-check" || finding.Parameter != "id" || finding.Status != "suspected" || finding.Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestIDORCheckConfirmsSecondaryIdentityReplay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte(`{"id":"1","owner":"alice","secret":"same-object"}`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/api/basket?id=1")
	input.Session.ToolParameters[models.SessionScanOptionsKey]["auth_headers"] = map[string]any{"Authorization": "Bearer alice"}
	input.Session.ToolParameters[models.SessionScanOptionsKey]["secondary_auth_headers"] = map[string]any{"Authorization": "Bearer bob"}
	out, err := NewIDORCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "idor-check" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestWorkflowAssistReportsGETStateChangingForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="get" action="/coupon/apply"><input name="coupon"><input name="cart_id" value="1"><input name="discount" value="25"><button>apply</button></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/coupon")
	adapter := NewWorkflowAssistCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected workflow assist to run with seeded coupon route")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "workflow-assist" || finding.Status != "suspected" || finding.Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if !strings.Contains(strings.ToLower(finding.Title), "workflow") {
		t.Fatalf("expected workflow title, got %q", finding.Title)
	}
}

func TestCSRFCheckReportsStateChangingFormWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="get" action="/change-password"><input name="password_new"><input name="password_conf"><button name="Change" value="Change">Change</button></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/csrf")
	adapter := NewCSRFCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected CSRF check to run with CSRF seed")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "csrf-check" || finding.Status != "suspected" || finding.Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestCSRFCheckIgnoresTokenizedForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="post" action="/profile"><input name="csrf_token" value="abc"><input name="email"></form>`))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/profile")
	out, err := NewCSRFCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestWeakSessionIDCheckConfirmsSequentialCookie(t *testing.T) {
	counter := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter++
		http.SetCookie(w, &http.Cookie{Name: "weakSessionID", Value: strconv.Itoa(counter), Path: "/"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/weak-session")
	adapter := NewWeakSessionIDCheck()
	if !adapter.ShouldRun(input) {
		t.Fatal("expected weak session check to run with weak session seed")
	}
	out, err := adapter.Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "weak-session-check" || finding.Parameter != "weakSessionID" || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestWeakSessionIDCheckSubmitsGenerationForm(t *testing.T) {
	counter := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post"><input type="submit" value="Generate"></form>`))
			return
		}
		counter++
		http.SetCookie(w, &http.Cookie{Name: "dvwaSession", Value: strconv.Itoa(counter), Path: "/"})
		_, _ = w.Write([]byte("generated"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/weak-session")
	out, err := NewWeakSessionIDCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d; stdout=%s", len(out.Findings), out.ToolRun.RawStdout)
	}
	finding := out.Findings[0]
	if finding.ToolID != "weak-session-check" || finding.Parameter != "dvwaSession" || finding.Method != http.MethodPost || finding.Status != "confirmed" || finding.Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestWeakSessionIDCheckIgnoresLongRandomCookie(t *testing.T) {
	counter := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter++
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "random-token-value-" + strconv.Itoa(counter) + "-with-length", Path: "/"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	input := testHTTPAdapterInput(t, server.URL, "/weak-session")
	out, err := NewWeakSessionIDCheck().Run(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", out.Findings)
	}
}

func TestParseSSTIFindings(t *testing.T) {
	findings := parseSSTIFindings(testExternalInput(), "https://example.com/?q={{7*7}}", "result: 49")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "ssti-check" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func testHTTPAdapterInput(t *testing.T, baseURL string, seeds ...string) AdapterInput {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(parsed.Port())
	session := models.Session{
		ID:          "session-1",
		Mode:        models.ScanModeActive,
		TargetInput: baseURL,
		ToolParameters: map[string]map[string]any{
			models.SessionScanOptionsKey: {
				"route_seeds": seeds,
			},
		},
		CreatedAt: time.Now().UTC(),
	}
	return AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target: models.Target{
			ID:        "target-1",
			SessionID: session.ID,
			Host:      parsed.Hostname(),
			Port:      port,
			Protocol:  parsed.Scheme,
			IsAlive:   true,
		},
		HTTPClient: http.DefaultClient,
	}
}

func TestParseXXEFindings(t *testing.T) {
	findings := parseXXEFindings(testExternalInput(), "https://example.com/", "nyx-xxe-marker", "resolved nyx-xxe-marker")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "xxe-fuzz" || findings[0].Severity != models.SeverityHigh || findings[0].Status != "confirmed" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseNiktoFindings(t *testing.T) {
	raw := `{"vulnerabilities":[{"msg":"OSVDB-1234: Example vulnerable file"}]}`
	findings := parseNiktoFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "nikto" || findings[0].Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseNiktoTextFindings(t *testing.T) {
	raw := `+ Target Hostname: 127.0.0.1
+ [95] /: Cookie PHPSESSID created without the httponly flag.
+ [013587] /: Suggested security header missing: x-content-type-options.
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.`
	findings := parseNiktoFindings(testExternalInput(), raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	for _, finding := range findings {
		if finding.ToolID != "nikto" || finding.Severity != models.SeverityMedium {
			t.Fatalf("unexpected finding: %#v", finding)
		}
	}
}

func testHasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
