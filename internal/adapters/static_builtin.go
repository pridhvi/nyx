package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
	"github.com/pridhvi/nox/internal/source"
)

func init() {
	for _, adapter := range []StaticAdapter{
		newCommandStaticAdapter("semgrep", "Semgrep", []string{"any"}, "semgrep", func(input StaticAdapterInput) []string {
			return []string{"scan", "--json", "--config", "p/security-audit", "--config", "p/secrets", "--config", "p/owasp-top-ten", input.RepoPath}
		}),
		newCommandStaticAdapter("bandit", "Bandit", []string{"python"}, "bandit", func(input StaticAdapterInput) []string {
			return []string{"-r", input.RepoPath, "-f", "json", "--severity-level", "low", "--confidence-level", "low"}
		}),
		newCommandStaticAdapter("gosec", "gosec", []string{"go"}, "gosec", func(input StaticAdapterInput) []string {
			return []string{"-fmt", "json", filepath.Join(input.RepoPath, "...")}
		}),
		newCommandStaticAdapter("govulncheck", "govulncheck", []string{"go"}, "govulncheck", func(input StaticAdapterInput) []string {
			return []string{"-json", input.RepoPath}
		}),
		newCommandStaticAdapter("npm-audit", "npm audit", []string{"javascript"}, "npm", func(input StaticAdapterInput) []string {
			return []string{"audit", "--json", "--prefix", input.RepoPath}
		}),
		newCommandStaticAdapter("retirejs", "retire.js", []string{"javascript"}, "retire", func(input StaticAdapterInput) []string {
			return []string{"--js", "--node", "--outputformat", "json", "--path", input.RepoPath}
		}),
		newCommandStaticAdapter("safety", "Safety", []string{"python"}, "safety", func(input StaticAdapterInput) []string {
			return []string{"check", "--json", "-r", filepath.Join(input.RepoPath, "requirements.txt")}
		}),
		newCommandStaticAdapter("brakeman", "Brakeman", []string{"ruby"}, "brakeman", func(input StaticAdapterInput) []string {
			return []string{"-f", "json", "-q", input.RepoPath}
		}),
		newCommandStaticAdapter("spotbugs", "SpotBugs", []string{"java"}, "spotbugs", func(input StaticAdapterInput) []string {
			return []string{"-textui", "-xml", input.RepoPath}
		}),
		newCommandStaticAdapter("psalm", "Psalm", []string{"php"}, "psalm", func(input StaticAdapterInput) []string {
			return []string{"--output-format=json", input.RepoPath}
		}),
		newCommandStaticAdapter("trufflehog", "TruffleHog", []string{"any"}, "trufflehog", func(input StaticAdapterInput) []string {
			return []string{"filesystem", input.RepoPath, "--json", "--no-update"}
		}),
		newCommandStaticAdapter("gitleaks", "gitleaks", []string{"any"}, "gitleaks", func(input StaticAdapterInput) []string {
			return []string{"detect", "--source", input.RepoPath, "--report-format", "json", "--no-git"}
		}),
		newCommandStaticAdapter("grype", "Grype", []string{"any"}, "grype", func(input StaticAdapterInput) []string {
			return []string{input.RepoPath, "-o", "json"}
		}),
		sourceStaticAdapter{id: "authmiddleware", name: "Auth middleware gap", kind: models.SourceKindUnprotectedRoute, severity: models.SeverityMedium},
		sourceStaticAdapter{id: "idor", name: "IDOR pattern detection", kind: models.SourceKindParameter, severity: models.SeverityMedium},
		sourceStaticAdapter{id: "dangerfuncs", name: "Dangerous function tracer", kind: models.SourceKindDeserialisationSink, severity: models.SeverityHigh},
		sourceStaticAdapter{id: "depconfusion", name: "Dependency confusion", kind: models.SourceKindSecret, severity: models.SeverityHigh},
	} {
		RegisterStatic(adapter)
	}
}

type commandStaticAdapter struct {
	id        string
	name      string
	languages []string
	binary    string
	args      func(StaticAdapterInput) []string
}

func newCommandStaticAdapter(id, name string, languages []string, binary string, args func(StaticAdapterInput) []string) commandStaticAdapter {
	return commandStaticAdapter{id: id, name: name, languages: languages, binary: binary, args: args}
}

func (a commandStaticAdapter) ID() string          { return a.id }
func (a commandStaticAdapter) Name() string        { return a.name }
func (a commandStaticAdapter) Languages() []string { return a.languages }
func (a commandStaticAdapter) Available() bool {
	_, err := exec.LookPath(a.binary)
	return err == nil
}
func (a commandStaticAdapter) Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error) {
	run := models.ToolRun{ID: models.NewID(), SessionID: input.SessionID, ToolID: a.id, Args: append([]string{a.binary}, a.args(input)...), StartedAt: time.Now().UTC()}
	result := RunCommand(ctx, 3*time.Minute, a.binary, a.args(input)...)
	run.RawStdout = result.Stdout
	run.RawStderr = result.Stderr
	run.ExitCode = result.ExitCode
	run.DurationMS = result.DurationMS
	now := time.Now().UTC()
	run.NormalizedAt = &now
	findings, cves := parseStaticOutput(input, a.id, result.Stdout)
	run.FindingCount = len(findings)
	return StaticAdapterOutput{Findings: findings, CVEs: cves, ToolRun: run}, nil
}

type sourceStaticAdapter struct {
	id       string
	name     string
	kind     models.SourceFindingKind
	severity models.Severity
}

func (a sourceStaticAdapter) ID() string          { return a.id }
func (a sourceStaticAdapter) Name() string        { return a.name }
func (a sourceStaticAdapter) Languages() []string { return []string{"any"} }
func (a sourceStaticAdapter) Available() bool     { return true }
func (a sourceStaticAdapter) Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error) {
	started := time.Now().UTC()
	result, _ := source.Analyse(input.RepoPath, input.SessionID)
	var findings []models.Finding
	for _, sourceFinding := range result.Findings {
		if sourceFinding.Kind != a.kind {
			continue
		}
		findings = append(findings, sourceFindingToAuditFinding(input.SessionID, a.id, a.severity, sourceFinding))
	}
	now := time.Now().UTC()
	return StaticAdapterOutput{Findings: findings, ToolRun: models.ToolRun{
		ID:           models.NewID(),
		SessionID:    input.SessionID,
		ToolID:       a.id,
		Args:         []string{a.id, input.RepoPath},
		ExitCode:     0,
		DurationMS:   time.Since(started).Milliseconds(),
		FindingCount: len(findings),
		NormalizedAt: &now,
		StartedAt:    started,
	}}, ctx.Err()
}

func parseStaticOutput(input StaticAdapterInput, toolID, raw string) ([]models.Finding, []models.CVEMatch) {
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, nil
	}
	var findings []models.Finding
	var cves []models.CVEMatch
	walkStaticJSON(decoded, func(obj map[string]any) {
		cveID := firstString(obj, "cve", "CVE", "id", "cve_id")
		if strings.HasPrefix(strings.ToUpper(cveID), "CVE-") || strings.HasPrefix(strings.ToUpper(cveID), "GHSA-") {
			cves = append(cves, models.CVEMatch{
				ID:              models.NewID(),
				SessionID:       input.SessionID,
				CVEID:           cveID,
				CVSSv3Score:     numberValue(obj, "cvss", "cvss_score", "score"),
				Description:     firstString(obj, "title", "summary", "description", "message"),
				PackageName:     firstString(obj, "package", "module", "name", "dependency"),
				PackageVersion:  firstString(obj, "version", "installed_version", "current_version"),
				AffectedVersion: firstString(obj, "affected_version", "installed_version", "version"),
				FixedVersion:    firstString(obj, "fixed_version", "fixed", "fix"),
				Source:          "audit/" + toolID,
				ConfidenceScore: 0.6,
			})
			return
		}
		file := firstString(obj, "path", "file", "filename", "component", "location")
		message := firstString(obj, "message", "issue_text", "details", "description", "check_id", "rule_id")
		if file == "" || message == "" || sourceFileExcluded(file) || !diffAllows(input.DiffPaths, file) {
			return
		}
		line := int(numberValue(obj, "line", "line_number", "start_line"))
		findings = append(findings, models.Finding{
			ID:          models.NewID(),
			SessionID:   input.SessionID,
			ToolID:      "audit/" + toolID,
			Type:        models.FindingTypeVulnerability,
			Severity:    severityFromString(firstString(obj, "severity", "issue_severity", "level")),
			Confidence:  0.5,
			Title:       message,
			Description: message,
			URL:         fileURL(file, line),
			EvidenceRaw: mustJSON(obj),
			CodeContext: firstString(obj, "code", "context", "extra"),
			Status:      "pending",
			Tags:        []string{"audit", toolID},
			CreatedAt:   time.Now().UTC(),
		})
	})
	return findings, cves
}

func sourceFindingToAuditFinding(sessionID, toolID string, severity models.Severity, sf models.SourceFinding) models.Finding {
	return models.Finding{
		ID:          models.NewID(),
		SessionID:   sessionID,
		ToolID:      "audit/" + toolID,
		Type:        models.FindingTypeVulnerability,
		Severity:    severity,
		Confidence:  0.45,
		Title:       fmt.Sprintf("%s detected in source", strings.ReplaceAll(string(sf.Kind), "_", " ")),
		Description: sf.Notes,
		URL:         fileURL(sf.FilePath, sf.LineNumber),
		Method:      sf.Method,
		EvidenceRaw: sf.Value,
		CodeContext: sf.Context,
		Status:      "pending",
		Tags:        []string{"audit", toolID, string(sf.Kind)},
		CreatedAt:   time.Now().UTC(),
	}
}

func walkStaticJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			walkStaticJSON(item, visit)
		}
	case map[string]any:
		visit(typed)
		for _, item := range typed {
			walkStaticJSON(item, visit)
		}
	}
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := obj[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case map[string]any:
				if nested := firstString(typed, keys...); nested != "" {
					return nested
				}
			}
		}
	}
	return ""
}

func numberValue(obj map[string]any, keys ...string) float64 {
	for _, key := range keys {
		switch typed := obj[key].(type) {
		case float64:
			return typed
		case int:
			return float64(typed)
		case json.Number:
			value, _ := typed.Float64()
			return value
		}
	}
	return 0
}

func severityFromString(value string) models.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return models.SeverityCritical
	case "error", "high":
		return models.SeverityHigh
	case "warning", "medium":
		return models.SeverityMedium
	case "low", "note", "info":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func fileURL(path string, line int) string {
	escaped := (&url.URL{Path: filepath.ToSlash(path)}).String()
	if line > 0 {
		return "file://" + escaped + fmt.Sprintf("#L%d", line)
	}
	return "file://" + escaped
}

func mustJSON(value any) string {
	body, _ := json.Marshal(value)
	return string(body)
}

func sourceFileExcluded(path string) bool {
	path = filepath.ToSlash(path)
	excluded := []string{"/__tests__/", "/test/", "/tests/", "/fixtures/", "_test.go", ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx"}
	for _, marker := range excluded {
		if strings.Contains(path, marker) || strings.HasPrefix(filepath.Base(path), "test_") {
			return true
		}
	}
	return false
}

func diffAllows(diffPaths []string, file string) bool {
	if len(diffPaths) == 0 {
		return true
	}
	file = filepath.ToSlash(file)
	for _, diffPath := range diffPaths {
		if file == filepath.ToSlash(diffPath) || strings.HasSuffix(file, filepath.ToSlash(diffPath)) {
			return true
		}
	}
	return false
}
