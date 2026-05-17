package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingSerializationAndValidation(t *testing.T) {
	finding := Finding{
		ID:                 "finding-1",
		SessionID:          "session-1",
		TargetID:           "target-1",
		ToolID:             "sqlmap",
		Type:               FindingTypeVulnerability,
		Severity:           SeverityHigh,
		Confidence:         0.91,
		CVSSScore:          8.8,
		Title:              "SQL injection",
		Description:        "Injected parameter accepted a boolean payload.",
		Remediation:        "Use parameterized queries.",
		URL:                "https://example.test/search?q=1",
		Parameter:          "q",
		Method:             "GET",
		EvidenceRaw:        "sqlmap output",
		EvidenceNormalized: `{"parameter":"q"}`,
		HTTPEvidence: &HTTPEvidence{
			FindingID:    "finding-1",
			RequestRaw:   "GET /search?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
			ResponseRaw:  "HTTP/1.1 200 OK\r\n\r\nok",
			StatusCode:   200,
			ResponseTime: 123,
		},
		Tags: []string{"owasp:A03", "cwe:89"},
		CVEMatches: []CVEMatch{{
			ID:               "cve-match-1",
			FindingID:        "finding-1",
			CVEID:            "CVE-2024-0001",
			CVSSv3Score:      7.5,
			CVSSv3Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description:      "Example CVE",
			PatchAvailable:   true,
			ExploitAvailable: false,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
			Source:           "nvd",
			ConfidenceScore:  0.8,
		}},
		CreatedAt: time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC),
	}

	if err := finding.Validate(); err != nil {
		t.Fatalf("expected finding to validate: %v", err)
	}
	assertJSONFields(t, finding, []string{
		"id", "session_id", "target_id", "tool_id", "type", "severity",
		"confidence", "cvss_score", "title", "description", "remediation",
		"url", "parameter", "method", "evidence_raw", "evidence_normalized",
		"http_evidence", "tags", "cve_matches", "created_at",
	})
}

func TestSessionTargetToolRunSerializationAndValidation(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	session := Session{
		ID:            "session-1",
		Name:          "Example engagement",
		Status:        SessionStatusRunning,
		Mode:          ScanModeActive,
		TargetInput:   "https://example.test",
		InScope:       []string{"example.test"},
		OutOfScope:    []string{"admin.example.test"},
		EnabledPhases: []string{"recon", "vuln"},
		LLMModel:      "llama3:8b",
		LLMBaseURL:    "http://localhost:11434/v1",
		TargetCount:   1,
		FindingCount:  2,
		StartedAt:     &now,
		CreatedAt:     now,
	}
	if err := session.Validate(); err != nil {
		t.Fatalf("expected session to validate: %v", err)
	}
	assertJSONFields(t, session, []string{
		"id", "name", "status", "mode", "target_input", "in_scope",
		"out_of_scope", "enabled_phases", "llm_model", "llm_base_url",
		"target_count", "finding_count", "started_at", "created_at",
	})

	target := Target{
		ID:           "target-1",
		SessionID:    "session-1",
		Host:         "example.test",
		IP:           "192.0.2.10",
		Port:         443,
		Protocol:     "https",
		IsAlive:      true,
		DiscoveredBy: "http-probe",
		CreatedAt:    now,
		Technologies: []Technology{{
			ID:         "tech-1",
			TargetID:   "target-1",
			Name:       "nginx",
			Version:    "1.25.0",
			Category:   "server",
			Confidence: 0.7,
			SourceTool: "whatweb",
		}},
	}
	if err := target.Technologies[0].Validate(); err != nil {
		t.Fatalf("expected technology to validate: %v", err)
	}
	if err := target.Validate(); err != nil {
		t.Fatalf("expected target to validate: %v", err)
	}
	assertJSONFields(t, target, []string{
		"id", "session_id", "host", "ip", "port", "protocol", "is_alive",
		"technologies", "discovered_by", "created_at",
	})

	run := ToolRun{
		ID:           "run-1",
		SessionID:    "session-1",
		TargetID:     "target-1",
		ToolID:       "nmap",
		Args:         []string{"-sV", "example.test"},
		StdoutPath:   "/tmp/run.stdout.log",
		StderrPath:   "/tmp/run.stderr.log",
		ExitCode:     0,
		DurationMS:   456,
		FindingCount: 1,
		NormalizedAt: &now,
		StartedAt:    now,
	}
	if err := run.Validate(); err != nil {
		t.Fatalf("expected tool run to validate: %v", err)
	}
	assertJSONFields(t, run, []string{
		"id", "session_id", "target_id", "tool_id", "args", "stdout_path",
		"stderr_path", "exit_code", "duration_ms", "finding_count",
		"normalized_at", "started_at",
	})
}

func TestSessionJSONRedactsScanAuthOptions(t *testing.T) {
	session := Session{
		ID:          "session-1",
		Status:      SessionStatusPending,
		Mode:        ScanModeActive,
		TargetInput: "https://example.test",
		ToolParameters: map[string]map[string]any{
			SessionScanOptionsKey: {
				"route_seeds":                  []string{"/admin"},
				"auth_headers":                 map[string]string{"Authorization": "Bearer secret"},
				"auth_cookie_header":           "session=secret",
				"auth_cookies":                 map[string]string{"csrftoken": "secret"},
				"auth_profile":                 map[string]any{"username": "alice", "password": "profile-secret"},
				"secondary_auth_headers":       map[string]string{"Authorization": "Bearer secondary"},
				"secondary_auth_cookie_header": "session=secondary",
				"non_sensitive_label":          "kept",
			},
			"ffuf": {
				"wordlist": "/tmp/words.txt",
			},
		},
		CreatedAt: time.Now().UTC(),
	}
	body, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "Bearer secret") || strings.Contains(text, "session=secret") || strings.Contains(text, "csrftoken") || strings.Contains(text, "profile-secret") || strings.Contains(text, "Bearer secondary") || strings.Contains(text, "session=secondary") {
		t.Fatalf("expected scan auth options to be redacted, got %s", text)
	}
	if !strings.Contains(text, "/admin") || !strings.Contains(text, "/tmp/words.txt") || !strings.Contains(text, "kept") {
		t.Fatalf("expected non-secret scan and tool options to remain visible, got %s", text)
	}
}

func TestCVEMatchAttackVectorAndReportSerializationAndValidation(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	cve := CVEMatch{
		ID:               "cve-match-1",
		TechnologyID:     "tech-1",
		CVEID:            "CVE-2024-0001",
		CVSSv3Score:      9.8,
		CVSSv3Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Description:      "Example vulnerability",
		AffectedVersion:  "1.2.3",
		FixedVersion:     "1.2.4",
		PatchAvailable:   true,
		ExploitAvailable: true,
		References:       []string{"https://example.test/cve"},
		Source:           "nvd",
		ConfidenceScore:  0.95,
	}
	if err := cve.Validate(); err != nil {
		t.Fatalf("expected CVE match to validate: %v", err)
	}
	assertJSONFields(t, cve, []string{
		"id", "technology_id", "cve_id", "cvss_v3_score", "cvss_v3_vector",
		"description", "affected_version", "fixed_version", "patch_available",
		"exploit_available", "references", "source", "confidence_score",
	})

	vector := AttackVector{
		ID:               "vector-1",
		SessionID:        "session-1",
		Title:            "Exploit injection to exfiltrate data",
		Description:      "Validated SQL injection can expose data.",
		Narrative:        "An attacker abuses the injectable search parameter.",
		OWASPCategory:    "A03:2021 - Injection",
		Severity:         SeverityCritical,
		Confidence:       0.86,
		PrereqFindingIDs: []string{"finding-1"},
		LLMReviewed:      true,
		LLMNotes:         "Narrative only; deterministic rule created the vector.",
		CreatedAt:        now,
		Steps: []AttackStep{{
			Order:         1,
			Description:   "Exploit injectable search parameter.",
			FindingID:     "finding-1",
			ToolSuggested: "sqlmap --level 5",
		}},
	}
	if err := vector.Validate(); err != nil {
		t.Fatalf("expected attack vector to validate: %v", err)
	}
	assertJSONFields(t, vector, []string{
		"id", "session_id", "title", "description", "narrative",
		"owasp_category", "severity", "confidence", "steps",
		"prereq_finding_ids", "llm_reviewed", "llm_notes", "created_at",
	})

	report := Report{
		ID:              "report-1",
		SessionID:       "session-1",
		Title:           "Example engagement report",
		Format:          ReportFormatHTML,
		Mode:            ReportModeTechnical,
		Summary:         "Two findings require remediation.",
		FindingIDs:      []string{"finding-1"},
		CVEMatchIDs:     []string{"cve-match-1"},
		AttackVectorIDs: []string{"vector-1"},
		GeneratedBy:     "nox",
		LLMGenerated:    false,
		CreatedAt:       now,
		Sections: []ReportSection{{
			ID:       ReportSectionExecutiveSummary,
			Title:    "Executive Summary",
			Content:  "Summary text.",
			Position: 1,
		}},
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("expected report to validate: %v", err)
	}
	assertJSONFields(t, report, []string{
		"id", "session_id", "title", "format", "mode", "summary", "sections",
		"finding_ids", "cve_match_ids", "attack_vector_ids", "generated_by",
		"llm_generated", "created_at",
	})
}

func TestValidationRejectsInvalidModelValues(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "finding confidence",
			err: Finding{
				ID: "finding-1", SessionID: "session-1", TargetID: "target-1",
				ToolID: "tool", Type: FindingTypeInfo, Severity: SeverityInfo,
				Title: "Info", Confidence: 1.2,
			}.Validate(),
			want: "confidence",
		},
		{
			name: "session mode",
			err: Session{
				ID: "session-1", Name: "Session", Status: SessionStatusPending,
				Mode: ScanMode("loud"), TargetInput: "https://example.test",
			}.Validate(),
			want: "mode",
		},
		{
			name: "cve link",
			err: CVEMatch{
				ID: "cve-match-1", CVEID: "CVE-2024-0001", Source: "nvd",
				CVSSv3Score: 5, ConfidenceScore: 0.6,
			}.Validate(),
			want: "finding_id or technology_id",
		},
		{
			name: "attack step order",
			err: AttackVector{
				ID: "vector-1", SessionID: "session-1", Title: "Vector",
				Severity: SeverityHigh, Confidence: 0.5,
				Steps: []AttackStep{{Description: "Missing order"}},
			}.Validate(),
			want: "order",
		},
		{
			name: "report format",
			err: Report{
				ID: "report-1", SessionID: "session-1", Title: "Report",
				Format: ReportFormat("docx"), Mode: ReportModeTechnical,
			}.Validate(),
			want: "format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(tt.err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %q", tt.want, tt.err.Error())
			}
		})
	}
}

func assertJSONFields(t *testing.T, value any, fields []string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal model: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal model: %v", err)
	}
	for _, field := range fields {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("expected JSON field %q in %s", field, encoded)
		}
	}
}
