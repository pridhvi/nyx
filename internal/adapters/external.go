package adapters

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

func activeOnly(input AdapterInput) bool {
	return input.Session.Mode == models.ScanModeActive
}

func targetBaseURL(target models.Target) string {
	return targetURL(target)
}

func sessionTargetURL(input AdapterInput) string {
	raw := strings.TrimSpace(input.Session.TargetInput)
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return raw
	}
	return targetBaseURL(input.Target)
}

func sessionTargetHasQuery(input AdapterInput) bool {
	parsed, err := url.Parse(sessionTargetURL(input))
	return err == nil && parsed.RawQuery != ""
}

func newToolRun(input AdapterInput, toolID string, args []string) models.ToolRun {
	return models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    toolID,
		Args:      args,
		StartedAt: time.Now().UTC(),
	}
}

func finishToolRun(run models.ToolRun, result CommandResult, findingCount int) models.ToolRun {
	run.RawStdout = result.Stdout
	run.RawStderr = result.Stderr
	run.ExitCode = result.ExitCode
	run.DurationMS = result.DurationMS
	run.FindingCount = findingCount
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return run
}

func failedToolRun(input AdapterInput, toolID string, args []string, message string, exitCode int) models.ToolRun {
	run := newToolRun(input, toolID, args)
	run.RawStderr = message
	run.ExitCode = exitCode
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return run
}

func sourceValues(findings []models.SourceFinding, kind models.SourceFindingKind) []string {
	seen := map[string]bool{}
	var values []string
	for _, finding := range findings {
		if finding.Kind != kind || strings.TrimSpace(finding.Value) == "" {
			continue
		}
		value := strings.TrimSpace(finding.Value)
		if !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

func toolParamString(input AdapterInput, name string) string {
	if input.ToolParameters == nil {
		return ""
	}
	value, ok := input.ToolParameters[name]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return strings.TrimSpace(toString(typed))
	}
}

func toolParamInt(input AdapterInput, name string, fallback int) int {
	if input.ToolParameters == nil {
		return fallback
	}
	value, ok := input.ToolParameters[name]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func toolParamBool(input AdapterInput, name string) bool {
	if input.ToolParameters == nil {
		return false
	}
	value, ok := input.ToolParameters[name]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	default:
		return false
	}
}

func toolParamStringList(input AdapterInput, name string) []string {
	if input.ToolParameters == nil {
		return nil
	}
	value, ok := input.ToolParameters[name]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return compactStrings(typed)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(toString(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		return compactStrings(strings.Fields(typed))
	default:
		text := strings.TrimSpace(toString(typed))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func boundedInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func commandTimeout(input AdapterInput, fallback time.Duration) time.Duration {
	seconds := toolParamInt(input, "timeout_seconds", 0)
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func externalFinding(input AdapterInput, toolID string, findingType models.FindingType, severity models.Severity, title, description, remediation, rawEvidence string, normalized any, tags []string) models.Finding {
	normalizedBody, _ := json.Marshal(normalized)
	return models.Finding{
		ID:                 models.NewID(),
		SessionID:          input.Session.ID,
		TargetID:           input.Target.ID,
		ToolID:             toolID,
		Type:               findingType,
		Severity:           severity,
		Confidence:         0.8,
		Title:              title,
		Description:        description,
		Remediation:        remediation,
		URL:                sessionTargetURL(input),
		EvidenceRaw:        rawEvidence,
		EvidenceNormalized: string(normalizedBody),
		Tags:               tags,
		CreatedAt:          time.Now().UTC(),
	}
}

func commonWordlistPath() string {
	for _, path := range []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
		"/usr/local/share/seclists/Discovery/Web-Content/common.txt",
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
