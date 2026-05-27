package adapters

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type SQLMap struct{}

func NewSQLMap() SQLMap {
	return SQLMap{}
}

func (SQLMap) ID() string { return "sqlmap" }

func (SQLMap) Name() string { return "sqlmap" }

func (SQLMap) Phase() Phase { return PhaseVulnScan }

func (SQLMap) DependsOn() []string { return []string{"ffuf"} }

func (SQLMap) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.IsAlive && hasVulnerabilityTargets(input)
}

func (a SQLMap) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	target := vulnerabilityTargetURL(input)
	level := boundedInt(toolParamInt(input, "level", 1), 1, 5)
	risk := boundedInt(toolParamInt(input, "risk", 1), 1, 3)
	args := []string{"-u", target, "--batch", "--level", strconv.Itoa(level), "--risk", strconv.Itoa(risk), "--technique", "BE", "--crawl", "0", "--timeout", "10", "--retries", "0", "--flush-session"}
	args = append(args, authCommandArgs(input, a.ID())...)
	args = append(args, toolParamStringList(input, "extra_args")...)
	displayArgs := redactCommandArgs(args)
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), displayArgs, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), displayArgs)
	result := RunCommand(ctx, commandTimeout(input, 90*time.Second), "sqlmap", args...)
	findings := parseSQLMapFindings(input, result.Stdout+"\n"+result.Stderr)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

func parseSQLMapFindings(input AdapterInput, raw string) []models.Finding {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "all tested parameters do not appear to be injectable") ||
		strings.Contains(lower, "does not seem to be injectable") ||
		strings.Contains(lower, "not injectable") {
		return nil
	}
	if !strings.Contains(lower, "is vulnerable") && !strings.Contains(lower, "appears to be injectable") {
		return nil
	}
	target := vulnerabilityTargetURL(input)
	parameter := firstQueryParameter(target)
	finding := externalFinding(
		input,
		"sqlmap",
		models.FindingTypeVulnerability,
		models.SeverityHigh,
		"Potential SQL injection",
		"sqlmap reported evidence consistent with an injectable HTTP parameter.",
		"Validate the affected parameter, use parameterized queries, and add regression tests for injection payloads.",
		raw,
		map[string]any{
			"url":       target,
			"parameter": parameter,
		},
		[]string{"sqlmap", "sqli"},
	)
	finding.Parameter = parameter
	return []models.Finding{finding}
}

func firstQueryParameter(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	for key := range parsed.Query() {
		return key
	}
	return ""
}
