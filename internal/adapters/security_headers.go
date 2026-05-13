package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

type SecurityHeaders struct{}

func NewSecurityHeaders() SecurityHeaders {
	return SecurityHeaders{}
}

func (SecurityHeaders) ID() string { return "security-headers" }

func (SecurityHeaders) Name() string { return "Security Headers" }

func (SecurityHeaders) Phase() Phase { return PhaseFingerprint }

func (SecurityHeaders) DependsOn() []string { return []string{"http-probe"} }

func (SecurityHeaders) ShouldRun(input AdapterInput) bool {
	return input.Target.IsAlive && (input.Target.Protocol == "http" || input.Target.Protocol == "https")
}

func (a SecurityHeaders) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	started := time.Now().UTC()
	url := targetURL(input.Target)
	run := models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    a.ID(),
		Args:      []string{url},
		StartedAt: started,
	}
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		run.ExitCode = 1
		run.StderrRaw = reason
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, fmt.Errorf("scope rejected %s: %s", input.Target.Host, reason)
	}
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		run.ExitCode = 1
		run.StderrRaw = err.Error()
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, err
	}
	req.Header.Set("User-Agent", "nox/0.1 security-headers")
	resp, err := client.Do(req)
	if err != nil {
		run.ExitCode = 1
		run.StderrRaw = err.Error()
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, err
	}
	defer resp.Body.Close()
	findings := headerFindings(input.Session.ID, input.Target.ID, url, resp.Header)
	observed := map[string]string{
		"content-security-policy":   resp.Header.Get("Content-Security-Policy"),
		"strict-transport-security": resp.Header.Get("Strict-Transport-Security"),
		"x-frame-options":           resp.Header.Get("X-Frame-Options"),
		"x-content-type-options":    resp.Header.Get("X-Content-Type-Options"),
		"referrer-policy":           resp.Header.Get("Referrer-Policy"),
	}
	normalized, _ := json.Marshal(observed)
	run.StdoutRaw = string(normalized)
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(started).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

func headerFindings(sessionID, targetID, url string, headers http.Header) []models.Finding {
	checks := []struct {
		header      string
		tag         string
		title       string
		description string
		remediation string
		severity    models.Severity
	}{
		{
			header:      "Content-Security-Policy",
			tag:         "missing-csp",
			title:       "Missing Content-Security-Policy header",
			description: "The response does not include a Content-Security-Policy header, which can increase the impact of cross-site scripting flaws.",
			remediation: "Define a restrictive Content-Security-Policy appropriate for the application.",
			severity:    models.SeverityLow,
		},
		{
			header:      "X-Frame-Options",
			tag:         "missing-x-frame-options",
			title:       "Missing X-Frame-Options header",
			description: "The response does not include X-Frame-Options, leaving browser framing policy undefined for older clients.",
			remediation: "Set X-Frame-Options to DENY or SAMEORIGIN, or enforce frame-ancestors in CSP.",
			severity:    models.SeverityLow,
		},
		{
			header:      "X-Content-Type-Options",
			tag:         "missing-x-content-type-options",
			title:       "Missing X-Content-Type-Options header",
			description: "The response does not include X-Content-Type-Options, which can allow MIME sniffing in some browsers.",
			remediation: "Set X-Content-Type-Options to nosniff.",
			severity:    models.SeverityInfo,
		},
		{
			header:      "Referrer-Policy",
			tag:         "missing-referrer-policy",
			title:       "Missing Referrer-Policy header",
			description: "The response does not define how much referrer information browsers should send to other origins.",
			remediation: "Set a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
			severity:    models.SeverityInfo,
		},
	}
	if strings.HasPrefix(url, "https://") {
		checks = append(checks, struct {
			header      string
			tag         string
			title       string
			description string
			remediation string
			severity    models.Severity
		}{
			header:      "Strict-Transport-Security",
			tag:         "missing-hsts",
			title:       "Missing Strict-Transport-Security header",
			description: "The HTTPS response does not include HSTS, so browsers are not instructed to require HTTPS on future visits.",
			remediation: "Set Strict-Transport-Security with an appropriate max-age after confirming HTTPS coverage.",
			severity:    models.SeverityLow,
		})
	}
	findings := make([]models.Finding, 0, len(checks))
	for _, check := range checks {
		if headers.Get(check.header) != "" {
			continue
		}
		evidence, _ := json.Marshal(map[string]string{"missing_header": check.header})
		findings = append(findings, models.Finding{
			ID:                 models.NewID(),
			SessionID:          sessionID,
			TargetID:           targetID,
			ToolID:             "security-headers",
			Type:               models.FindingTypeMisconfiguration,
			Severity:           check.severity,
			Confidence:         0.95,
			Title:              check.title,
			Description:        check.description,
			Remediation:        check.remediation,
			URL:                url,
			Method:             http.MethodGet,
			EvidenceNormalized: string(evidence),
			Tags:               []string{check.tag, "headers"},
			CreatedAt:          time.Now().UTC(),
		})
	}
	return findings
}
