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
