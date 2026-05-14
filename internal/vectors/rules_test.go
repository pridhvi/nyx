package vectors

import (
	"testing"

	"github.com/kanini/nox/internal/models"
)

func TestDefaultRulesGenerateExpectedVectors(t *testing.T) {
	cases := []struct {
		name     string
		findings []models.Finding
		want     string
	}{
		{
			name: "xss with missing csp",
			findings: []models.Finding{
				finding("xss", "dalfox", models.FindingTypeVulnerability, models.SeverityHigh, "https://example.com/?q=x", "q", []string{"xss"}),
				finding("csp", "security-headers", models.FindingTypeMisconfiguration, models.SeverityLow, "https://example.com/", "", []string{"missing-csp"}),
			},
			want: "Reflected XSS with missing Content-Security-Policy",
		},
		{
			name:     "ssrf metadata",
			findings: []models.Finding{finding("ssrf", "ssrfmap", models.FindingTypeVulnerability, models.SeverityHigh, "https://example.com/?url=x", "url", []string{"ssrf"})},
			want:     "SSRF path to cloud metadata access",
		},
		{
			name:     "weak jwt",
			findings: []models.Finding{finding("jwt", "jwt-tool", models.FindingTypeVulnerability, models.SeverityCritical, "https://example.com/", "", []string{"weak-secret"})},
			want:     "Weak JWT signing controls enable token forgery",
		},
		{
			name:     "sql injection",
			findings: []models.Finding{finding("sqli", "sqlmap", models.FindingTypeVulnerability, models.SeverityHigh, "https://example.com/?q=x", "q", []string{"sqli"})},
			want:     "Unauthenticated SQL injection path",
		},
		{
			name: "admin default auth",
			findings: []models.Finding{
				finding("admin", "ffuf", models.FindingTypeExposure, models.SeverityLow, "https://example.com/admin", "", []string{"admin-panel"}),
				finding("default", "nikto", models.FindingTypeVulnerability, models.SeverityMedium, "https://example.com/admin", "", []string{"default-credentials"}),
			},
			want: "Exposed admin surface with weak/default auth indicators",
		},
		{
			name:     "cors wildcard credentials",
			findings: []models.Finding{finding("cors", "cors-check", models.FindingTypeMisconfiguration, models.SeverityMedium, "https://example.com/", "", []string{"cors-wildcard-credentials"})},
			want:     "CORS wildcard credentials attack path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vectors := NewEngine().Generate("session-1", tc.findings, nil)
			if len(vectors) != 1 {
				t.Fatalf("expected 1 vector, got %#v", vectors)
			}
			if vectors[0].Title != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, vectors[0].Title)
			}
			if len(vectors[0].Steps) == 0 || len(vectors[0].PrereqFindingIDs) == 0 {
				t.Fatalf("expected steps and prereqs: %#v", vectors[0])
			}
			if vectors[0].LLMReviewed {
				t.Fatal("deterministic vector should not be marked LLM reviewed")
			}
		})
	}
}

func TestCVEVectorGeneration(t *testing.T) {
	cves := []models.CVEMatch{{
		FindingID:        "finding-1",
		CVEID:            "CVE-2024-0001",
		CVSSv3Score:      9.1,
		Description:      "Example exploitable CVE",
		ExploitAvailable: true,
		ConfidenceScore:  0.9,
	}}
	vectors := NewEngine().Generate("session-1", nil, cves)
	if len(vectors) != 1 {
		t.Fatalf("expected 1 vector, got %#v", vectors)
	}
	if vectors[0].Severity != models.SeverityCritical || vectors[0].PrereqFindingIDs[0] != "finding-1" {
		t.Fatalf("unexpected CVE vector: %#v", vectors[0])
	}
}

func TestRuleRequiresAllConditions(t *testing.T) {
	findings := []models.Finding{
		finding("xss", "dalfox", models.FindingTypeVulnerability, models.SeverityHigh, "https://example.com/?q=x", "q", []string{"xss"}),
	}
	vectors := NewEngine().Generate("session-1", findings, nil)
	if len(vectors) != 0 {
		t.Fatalf("expected no vector without missing CSP, got %#v", vectors)
	}
}

func finding(id, toolID string, findingType models.FindingType, severity models.Severity, rawURL, parameter string, tags []string) models.Finding {
	return models.Finding{
		ID:         id,
		SessionID:  "session-1",
		TargetID:   "target-1",
		ToolID:     toolID,
		Type:       findingType,
		Severity:   severity,
		Confidence: 0.9,
		Title:      id,
		URL:        rawURL,
		Parameter:  parameter,
		Tags:       tags,
	}
}
