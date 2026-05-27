package adapters

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type Dalfox struct{}

func NewDalfox() Dalfox {
	return Dalfox{}
}

func (Dalfox) ID() string { return "dalfox" }

func (Dalfox) Name() string { return "Dalfox" }

func (Dalfox) Phase() Phase { return PhaseVulnScan }

func (Dalfox) DependsOn() []string { return []string{"ffuf", "dom-xss-check"} }

func (Dalfox) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.IsAlive && hasVulnerabilityTargets(input)
}

func (a Dalfox) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	target := vulnerabilityTargetURL(input)
	args := []string{"url", target, "--format", "json", "--silence"}
	if blind := toolParamString(input, "blind"); blind != "" {
		args = append(args, "--blind", blind)
	}
	if toolParamBool(input, "skip_grepping") {
		args = append(args, "--skip-grepping")
	}
	args = append(args, authCommandArgs(input, a.ID())...)
	args = append(args, toolParamStringList(input, "extra_args")...)
	displayArgs := redactCommandArgs(args)
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), displayArgs, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), displayArgs)
	result := RunCommand(ctx, commandTimeout(input, 90*time.Second), "dalfox", args...)
	findings := parseDalfoxFindings(input, result.Stdout)
	if len(findings) == 0 {
		findings = parseDalfoxTextFindings(input, result.Stdout+"\n"+result.Stderr)
	}
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

func parseDalfoxFindings(input AdapterInput, raw string) []models.Finding {
	var objects []map[string]any
	if err := json.Unmarshal([]byte(raw), &objects); err != nil {
		var object map[string]any
		if err := json.Unmarshal([]byte(raw), &object); err != nil {
			return nil
		}
		objects = []map[string]any{object}
	}
	var findings []models.Finding
	for _, object := range objects {
		if len(object) == 0 {
			continue
		}
		param := stringValue(object, "param")
		if param == "" {
			param = stringValue(object, "parameter")
		}
		poc := stringValue(object, "poc")
		if poc == "" {
			poc = stringValue(object, "payload")
		}
		finding := externalFinding(
			input,
			"dalfox",
			models.FindingTypeVulnerability,
			models.SeverityHigh,
			"Potential cross-site scripting",
			"Dalfox reported evidence consistent with cross-site scripting.",
			"Encode untrusted output in the correct browser context and validate or reject dangerous input.",
			raw,
			object,
			[]string{"dalfox", "xss"},
		)
		finding.Parameter = param
		if poc != "" {
			finding.Description += " Proof of concept payload was captured in evidence."
		}
		findings = append(findings, finding)
	}
	return findings
}

func parseDalfoxTextFindings(input AdapterInput, raw string) []models.Finding {
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "vulnerable") && !strings.Contains(lower, "verified") && !strings.Contains(lower, "xss") {
		return nil
	}
	finding := externalFinding(
		input,
		"dalfox",
		models.FindingTypeVulnerability,
		models.SeverityHigh,
		"Potential cross-site scripting",
		"Dalfox output included XSS indicators. Review the raw evidence to confirm the affected parameter and payload.",
		"Encode untrusted output in the correct browser context and validate or reject dangerous input.",
		raw,
		map[string]any{"url": vulnerabilityTargetURL(input)},
		[]string{"dalfox", "xss"},
	)
	finding.Parameter = firstQueryParameter(vulnerabilityTargetURL(input))
	return []models.Finding{finding}
}

func stringValue(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
