package adapters

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type Nikto struct{}

func NewNikto() Nikto                           { return Nikto{} }
func (Nikto) ID() string                        { return "nikto" }
func (Nikto) Name() string                      { return "Nikto" }
func (Nikto) Phase() Phase                      { return PhaseVulnScan }
func (Nikto) DependsOn() []string               { return []string{"security-headers", "dom-xss-check"} }
func (Nikto) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a Nikto) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	outputFile, err := os.CreateTemp("", "nyx-nikto-*.json")
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), []string{"-host", rawURL, "-Format", "json", "-nointeractive"}, err.Error(), 1)}, nil
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer os.Remove(outputPath)
	args := []string{"-host", rawURL, "-Format", "json", "-output", outputPath, "-nointeractive", "-ask", "no", "-nocheck", "-timeout", "5", "-maxtime", "75s"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 120*time.Second, "nikto", args...)
	if body, err := os.ReadFile(outputPath); err == nil && len(body) > 0 { // #nosec G304 -- outputPath is a Nyx-created temporary nikto output file.
		result.Stdout = string(body)
	}
	findings := parseNiktoFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

func parseNiktoFindings(input AdapterInput, raw string) []models.Finding {
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err == nil {
		if vulnerabilities, ok := body["vulnerabilities"].([]any); ok {
			return niktoRows(input, raw, vulnerabilities)
		}
		if hosts, ok := body["host"].([]any); ok {
			var rows []any
			for _, host := range hosts {
				if object, ok := host.(map[string]any); ok {
					if vulns, ok := object["vulnerabilities"].([]any); ok {
						rows = append(rows, vulns...)
					}
				}
			}
			return niktoRows(input, raw, rows)
		}
	}
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !looksLikeNiktoFindingLine(line) {
			continue
		}
		findings = append(findings, externalFinding(input, "nikto", models.FindingTypeVulnerability, models.SeverityMedium, "Nikto web server finding", line, "Review and remediate the web server issue reported by Nikto.", raw, map[string]any{"line": line}, []string{"nikto", "web-server"}))
	}
	return findings
}

func looksLikeNiktoFindingLine(line string) bool {
	if !strings.HasPrefix(line, "+") {
		return false
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "+ target ") ||
		strings.HasPrefix(lower, "+ start time:") ||
		strings.HasPrefix(lower, "+ end time:") ||
		strings.HasPrefix(lower, "+ 1 host") ||
		strings.HasPrefix(lower, "+ no cgi") ||
		strings.Contains(lower, "items checked:") ||
		strings.Contains(lower, "error: failed to check for updates") {
		return false
	}
	for _, marker := range []string{
		"osvdb", "vulner", "header missing", "cookie", "allowed http methods", "directory indexing", "interesting", "admin", "default", "outdated", "disclosure",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func niktoRows(input AdapterInput, raw string, rows []any) []models.Finding {
	var findings []models.Finding
	for _, row := range rows {
		object, ok := row.(map[string]any)
		if !ok {
			continue
		}
		msg := firstNonEmpty(stringField(object, "msg"), stringField(object, "message"), stringField(object, "description"))
		if msg == "" {
			continue
		}
		findings = append(findings, externalFinding(input, "nikto", models.FindingTypeVulnerability, models.SeverityMedium, "Nikto web server finding", msg, "Review and remediate the web server issue reported by Nikto.", raw, object, []string{"nikto", "web-server"}))
	}
	return findings
}
