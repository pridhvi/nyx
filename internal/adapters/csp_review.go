package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type CSPReviewCheck struct{}

func NewCSPReviewCheck() CSPReviewCheck { return CSPReviewCheck{} }
func (CSPReviewCheck) ID() string       { return "csp-review" }
func (CSPReviewCheck) Name() string     { return "CSP Review" }
func (CSPReviewCheck) Phase() Phase     { return PhaseVulnScan }
func (CSPReviewCheck) DependsOn() []string {
	return []string{"security-headers"}
}
func (CSPReviewCheck) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && liveHTTP(input) && len(cspReviewCandidateURLs(input, cspReviewLimit(input))) > 0
}
func (a CSPReviewCheck) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	candidates := cspReviewCandidateURLs(input, cspReviewLimit(input))
	args := candidates
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	raw := []string{fmt.Sprintf("candidates=%d", len(candidates))}
	if input.Scope != nil && HasAuthProfile(input.Session) {
		result, err := ResolveSessionAuth(ctx, input.Session, input.Target, input.Scope)
		if err == nil && result.Applied {
			input.Session = result.Session
			raw = append(raw, "auth_refreshed=true")
		} else if err != nil {
			raw = append(raw, "auth_refresh_error="+err.Error())
		}
	}
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	var findings []models.Finding
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if ok, reason := targetInScopeURL(input, candidate); !ok {
			raw = append(raw, fmt.Sprintf("%s skip_reason=%s", candidate, reason))
			continue
		}
		resp, body, err := httpGetWithResponse(ctx, input, client, candidate, "nyx/0.1 csp-review")
		if err != nil {
			raw = append(raw, fmt.Sprintf("%s error=%s", candidate, err))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			raw = append(raw, fmt.Sprintf("%s status=%d skipped=true", candidate, resp.StatusCode))
			continue
		}
		policies := cspPolicies(resp.Header, body)
		forms := parseHTMLForms(candidate, body)
		reasons := cspReviewReasons(input, policies)
		sourceFields := cspSourceControlFields(forms)
		surface := looksLikeCSPReviewSurface(candidate) || bodyLooksLikeCSPReviewSurface(body) || len(sourceFields) > 0
		raw = append(raw, fmt.Sprintf("%s status=%d policies=%d forms=%d source_fields=%d reasons=%d", candidate, resp.StatusCode, len(policies), len(forms), len(sourceFields), len(reasons)))
		if !surface || len(policies) == 0 || len(reasons) == 0 {
			continue
		}
		signature := candidate + "\x00" + strings.Join(policies, "\x00") + "\x00" + strings.Join(sourceFields, ",")
		if seen[signature] {
			continue
		}
		seen[signature] = true
		findings = append(findings, cspReviewFinding(input, candidate, resp.StatusCode, policies, reasons, sourceFields))
	}
	run.RawStdout = strings.Join(raw, "\n")
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

func cspReviewLimit(input AdapterInput) int {
	limit := toolParamInt(input, "max_pages", 0)
	if limit <= 0 {
		return 10
	}
	if limit > 25 {
		return 25
	}
	return limit
}

func cspReviewCandidateURLs(input AdapterInput, limit int) []string {
	var urls []string
	if looksLikeCSPReviewSurface(sessionTargetURL(input)) {
		urls = append(urls, sessionTargetURL(input))
	}
	for _, rawURL := range seededURLs(input) {
		if looksLikeCSPReviewSurface(rawURL) {
			urls = append(urls, rawURL)
		}
	}
	for _, route := range sourceValues(input.SourceFindings, models.SourceKindRoute) {
		if looksLikeCSPReviewSurface(route) {
			urls = append(urls, normalizeSeedURL(input.Target, route))
		}
	}
	return limitedScopedURLs(input, urls, limit)
}

func looksLikeCSPReviewSurface(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "csp") ||
		strings.Contains(lower, "content-security-policy") ||
		strings.Contains(lower, "script-src")
}

func bodyLooksLikeCSPReviewSurface(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "content security policy") ||
		strings.Contains(lower, "content-security-policy") ||
		strings.Contains(lower, "script-src")
}

func cspPolicies(headers http.Header, body string) []string {
	var policies []string
	for _, value := range headers.Values("Content-Security-Policy") {
		value = strings.TrimSpace(value)
		if value != "" {
			policies = append(policies, value)
		}
	}
	for _, attrs := range metaTagAttrs(body) {
		if !strings.EqualFold(attrValue(attrs, "http-equiv"), "Content-Security-Policy") {
			continue
		}
		if content := strings.TrimSpace(attrValue(attrs, "content")); content != "" {
			policies = append(policies, content)
		}
	}
	return dedupeStrings(policies)
}

func metaTagAttrs(body string) []string {
	matches := regexp.MustCompile(`(?is)<meta\b([^>]*)>`).FindAllStringSubmatch(body, -1)
	attrs := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			attrs = append(attrs, match[1])
		}
	}
	return attrs
}

func cspReviewReasons(input AdapterInput, policies []string) []string {
	seen := map[string]bool{}
	var reasons []string
	add := func(reason string) {
		if reason = strings.TrimSpace(reason); reason != "" && !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
	}
	for _, policy := range policies {
		directives := cspDirectives(policy)
		scriptSources := directives["script-src"]
		if len(scriptSources) == 0 {
			scriptSources = directives["default-src"]
		}
		if len(scriptSources) == 0 {
			add("policy does not define script-src or default-src")
			continue
		}
		for _, source := range scriptSources {
			normalized := strings.ToLower(strings.Trim(source, " \t\r\n"))
			switch normalized {
			case "'unsafe-inline'", "unsafe-inline":
				add("script-src allows unsafe-inline")
			case "'unsafe-eval'", "unsafe-eval":
				add("script-src allows unsafe-eval")
			case "*":
				add("script-src allows wildcard sources")
			case "http:", "https:", "data:", "blob:":
				add("script-src allows broad scheme source " + normalized)
			}
			if cspSourceLooksExternal(input.Target.Host, normalized) {
				add("script-src allows external script source " + source)
			}
		}
	}
	return reasons
}

func cspDirectives(policy string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		out[name] = fields[1:]
	}
	return out
}

func cspSourceLooksExternal(targetHost, source string) bool {
	source = strings.Trim(source, "\"'")
	if source == "" || source == "self" || source == "none" || source == "strict-dynamic" || strings.HasPrefix(source, "nonce-") || strings.HasPrefix(source, "sha") {
		return false
	}
	host := cspSourceHost(source)
	if host == "" {
		return false
	}
	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	host = strings.TrimPrefix(strings.ToLower(host), "*.")
	return host != targetHost && !strings.HasSuffix(host, "."+targetHost)
}

func cspSourceHost(source string) string {
	if strings.Contains(source, "://") {
		parsed, err := url.Parse(source)
		if err == nil {
			return parsed.Hostname()
		}
	}
	if strings.Contains(source, ".") {
		host := strings.Trim(source, "/")
		if idx := strings.IndexAny(host, "/:"); idx >= 0 {
			host = host[:idx]
		}
		return host
	}
	return ""
}

func cspSourceControlFields(forms []htmlForm) []string {
	seen := map[string]bool{}
	var fields []string
	for _, form := range forms {
		for _, field := range sortedMapKeys(form.Fields) {
			if !fieldLooksLikeScriptSource(field) {
				continue
			}
			entry := strings.ToUpper(form.Method) + " " + form.Action + "#" + field
			if !seen[entry] {
				seen[entry] = true
				fields = append(fields, entry)
			}
		}
	}
	return fields
}

func fieldLooksLikeScriptSource(field string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(field, "-", ""), "_", ""))
	for _, marker := range []string{"include", "script", "src", "source", "url", "uri", "href", "cdn", "callback"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func cspReviewFinding(input AdapterInput, rawURL string, statusCode int, policies, reasons, sourceFields []string) models.Finding {
	evidence, _ := json.Marshal(map[string]any{
		"url":           rawURL,
		"status_code":   statusCode,
		"policies":      policies,
		"risk_reasons":  reasons,
		"source_fields": sourceFields,
		"validated":     false,
		"human_assist":  true,
	})
	finding := externalFinding(input, "csp-review", models.FindingTypeVulnerability, models.SeverityMedium, "Potential CSP bypass review candidate", "A seeded page combines a script policy that may allow bypass research with a CSP-related surface or user-controlled script/source field. This is a human-assist candidate and does not prove bypass execution.", "Review the script-src policy, remove unnecessary external script sources, avoid user-controlled script include flows, and prefer nonces or hashes with strict-dynamic where appropriate.", string(evidence), map[string]any{"url": rawURL, "policies": policies, "risk_reasons": reasons, "source_fields": sourceFields, "validated": false, "human_assist": true}, []string{"csp", "csp-bypass", "human-assist"})
	finding.URL = rawURL
	finding.Method = http.MethodGet
	finding.Status = "suspected"
	finding.Confidence = 0.55
	return finding
}
