package adapters

import (
	"testing"
	"time"

	"github.com/kanini/nox/internal/models"
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
	raw := `<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port></ports></host></nmaprun>`
	findings := parseNmapFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "nmap" || findings[0].Type != models.FindingTypeExposure || findings[0].Severity != models.SeverityInfo {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].EvidenceRaw == "" || findings[0].EvidenceNormalized == "" {
		t.Fatal("expected raw and normalized evidence")
	}
}

func TestParseFFUFFindings(t *testing.T) {
	raw := `{"results":[{"url":"https://example.com/admin","status":200,"length":42,"words":4,"lines":1}]}`
	findings := parseFFUFFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "ffuf" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
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
	findings := parseCORSFindings(testExternalInput(), "https://example.com/", "https://nox.invalid", headers, `{"access-control-allow-origin":"*"}`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "cors-check" || findings[0].Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if !hasTag(findings[0].Tags, "cors-wildcard-credentials") {
		t.Fatalf("expected cors-wildcard-credentials tag, got %#v", findings[0].Tags)
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

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
