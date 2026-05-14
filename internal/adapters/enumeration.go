package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

type Arjun struct{}

func NewArjun() Arjun                           { return Arjun{} }
func (Arjun) ID() string                        { return "arjun" }
func (Arjun) Name() string                      { return "Arjun" }
func (Arjun) Phase() Phase                      { return PhaseEnumerate }
func (Arjun) DependsOn() []string               { return []string{"security-headers"} }
func (Arjun) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a Arjun) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"-u", rawURL, "-oJ", "-"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 90*time.Second, "arjun", args...)
	findings := parseArjunFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type LinkFinder struct{}

func NewLinkFinder() LinkFinder                      { return LinkFinder{} }
func (LinkFinder) ID() string                        { return "linkfinder" }
func (LinkFinder) Name() string                      { return "LinkFinder" }
func (LinkFinder) Phase() Phase                      { return PhaseEnumerate }
func (LinkFinder) DependsOn() []string               { return []string{"security-headers"} }
func (LinkFinder) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a LinkFinder) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"-i", rawURL, "-o", "cli"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "linkfinder", args...)
	findings := parseEndpointFindings(input, "linkfinder", result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type Gitleaks struct{}

func NewGitleaks() Gitleaks                        { return Gitleaks{} }
func (Gitleaks) ID() string                        { return "gitleaks" }
func (Gitleaks) Name() string                      { return "gitleaks" }
func (Gitleaks) Phase() Phase                      { return PhaseEnumerate }
func (Gitleaks) DependsOn() []string               { return []string{"security-headers"} }
func (Gitleaks) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a Gitleaks) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"detect", "--no-git", "--source", rawURL, "--report-format", "json", "--report-path", "-"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 90*time.Second, "gitleaks", args...)
	findings := parseGitleaksFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type JavaScriptSecretScan struct{}

func NewJavaScriptSecretScan() JavaScriptSecretScan { return JavaScriptSecretScan{} }
func (JavaScriptSecretScan) ID() string             { return "js-secret-scan" }
func (JavaScriptSecretScan) Name() string           { return "JavaScript Secret Scan" }
func (JavaScriptSecretScan) Phase() Phase           { return PhaseEnumerate }
func (JavaScriptSecretScan) DependsOn() []string    { return []string{"security-headers"} }
func (JavaScriptSecretScan) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && liveHTTP(input)
}
func (a JavaScriptSecretScan) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{rawURL}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	raw, findings := fetchAndScanScripts(ctx, input, client, rawURL)
	run.StdoutRaw = raw
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

type CORSCheck struct{}

func NewCORSCheck() CORSCheck                       { return CORSCheck{} }
func (CORSCheck) ID() string                        { return "cors-check" }
func (CORSCheck) Name() string                      { return "CORS Check" }
func (CORSCheck) Phase() Phase                      { return PhaseEnumerate }
func (CORSCheck) DependsOn() []string               { return []string{"security-headers"} }
func (CORSCheck) ShouldRun(input AdapterInput) bool { return liveHTTP(input) }
func (a CORSCheck) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{rawURL}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	origin := "https://nox.invalid"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "nox/0.1 cors-check")
	resp, err := client.Do(req)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	defer resp.Body.Close()
	headers := map[string]string{
		"access-control-allow-origin":      resp.Header.Get("Access-Control-Allow-Origin"),
		"access-control-allow-credentials": resp.Header.Get("Access-Control-Allow-Credentials"),
		"vary":                             resp.Header.Get("Vary"),
	}
	normalized, _ := json.Marshal(headers)
	findings := parseCORSFindings(input, rawURL, origin, headers, string(normalized))
	run.StdoutRaw = string(normalized)
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

type CloudBucketCheck struct{}

func NewCloudBucketCheck() CloudBucketCheck  { return CloudBucketCheck{} }
func (CloudBucketCheck) ID() string          { return "cloud-bucket-check" }
func (CloudBucketCheck) Name() string        { return "Cloud Bucket Check" }
func (CloudBucketCheck) Phase() Phase        { return PhaseEnumerate }
func (CloudBucketCheck) DependsOn() []string { return []string{"security-headers"} }
func (CloudBucketCheck) ShouldRun(input AdapterInput) bool {
	host := strings.ToLower(input.Target.Host)
	return liveHTTP(input) && (strings.Contains(host, "s3.amazonaws.com") || strings.Contains(host, "storage.googleapis.com") || strings.Contains(host, "googleapis.com"))
}
func (a CloudBucketCheck) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{rawURL}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	req.Header.Set("User-Agent", "nox/0.1 cloud-bucket-check")
	resp, err := client.Do(req)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	findings := parseCloudBucketFindings(input, rawURL, resp.StatusCode, string(body))
	run.StdoutRaw = string(body)
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

func parseArjunFindings(input AdapterInput, raw string) []models.Finding {
	params := map[string]bool{}
	var body any
	if err := json.Unmarshal([]byte(raw), &body); err == nil {
		collectParams(body, params)
	} else {
		for _, match := range parameterPattern.FindAllStringSubmatch(raw, -1) {
			params[match[1]] = true
		}
	}
	var findings []models.Finding
	for param := range params {
		finding := externalFinding(input, "arjun", models.FindingTypeInfo, models.SeverityInfo, "Hidden HTTP parameter discovered", fmt.Sprintf("Arjun discovered hidden HTTP parameter %q.", param), "Review whether the parameter changes application behavior before using it in later tests.", raw, map[string]any{"parameter": param}, []string{"arjun", "hidden-parameter"})
		finding.Parameter = param
		findings = append(findings, finding)
	}
	return findings
}

func collectParams(value any, out map[string]bool) {
	switch typed := value.(type) {
	case string:
		if parameterName(typed) {
			out[typed] = true
		}
	case []any:
		for _, item := range typed {
			collectParams(item, out)
		}
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, "params") || strings.EqualFold(key, "parameters") {
				collectParams(item, out)
			} else if parameterName(key) && scalarParamValue(item) {
				out[key] = true
			} else {
				collectParams(item, out)
			}
		}
	}
}

func scalarParamValue(value any) bool {
	switch value.(type) {
	case string, float64, bool, nil:
		return true
	default:
		return false
	}
}

func parameterName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	return parameterNamePattern.MatchString(value)
}

func parseEndpointFindings(input AdapterInput, toolID, raw string) []models.Finding {
	seen := map[string]bool{}
	var findings []models.Finding
	for _, endpoint := range endpointCandidates(raw) {
		absolute := resolveEndpoint(input.Target, endpoint)
		if absolute == "" || seen[absolute] {
			continue
		}
		parsed, err := url.Parse(absolute)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if ok, _ := targetInScope(input, parsed.Hostname()); !ok {
			continue
		}
		seen[absolute] = true
		findings = append(findings, externalFinding(input, toolID, models.FindingTypeInfo, models.SeverityInfo, "JavaScript endpoint discovered", fmt.Sprintf("%s discovered endpoint %s.", toolID, absolute), "Review discovered endpoints for authorization and input validation coverage.", raw, map[string]any{"url": absolute, "path": parsed.Path}, []string{toolID, "javascript-endpoint"}))
	}
	return findings
}

func endpointCandidates(raw string) []string {
	matches := endpointPattern.FindAllString(raw, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.Trim(match, `"' <>`)
		if strings.HasPrefix(match, "//") {
			match = "https:" + match
		}
		values = append(values, match)
	}
	return values
}

func resolveEndpoint(target models.Target, endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	base, err := url.Parse(targetURL(target))
	if err != nil {
		return ""
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func parseGitleaksFindings(input AdapterInput, raw string) []models.Finding {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		for _, line := range strings.Split(raw, "\n") {
			var row map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &row) == nil {
				rows = append(rows, row)
			}
		}
	}
	var findings []models.Finding
	for _, row := range rows {
		rule := firstNonEmpty(stringField(row, "RuleID"), stringField(row, "Description"), stringField(row, "rule"))
		secret := firstNonEmpty(stringField(row, "Secret"), stringField(row, "secret"), stringField(row, "Match"))
		if rule == "" && secret == "" {
			continue
		}
		findings = append(findings, externalFinding(input, "gitleaks", models.FindingTypeExposure, models.SeverityHigh, "Potential secret exposed", "gitleaks reported a potential secret in enumerated content.", "Revoke the exposed credential if valid, remove it from public content, and rotate dependent secrets.", raw, row, []string{"gitleaks", "secret", "exposed-secret"}))
	}
	return findings
}

func fetchAndScanScripts(ctx context.Context, input AdapterInput, client HTTPDoer, rawURL string) (string, []models.Finding) {
	pageBody, err := fetchText(ctx, client, rawURL)
	if err != nil {
		return err.Error(), nil
	}
	rawParts := []string{rawURL + "\n" + pageBody}
	findings := scanSecretFindings(input, "js-secret-scan", rawURL, pageBody)
	for _, scriptURL := range scriptURLs(input.Target, pageBody) {
		parsed, err := url.Parse(scriptURL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if ok, _ := targetInScope(input, parsed.Hostname()); !ok {
			continue
		}
		body, err := fetchText(ctx, client, scriptURL)
		if err != nil {
			rawParts = append(rawParts, scriptURL+"\n"+err.Error())
			continue
		}
		rawParts = append(rawParts, scriptURL+"\n"+body)
		findings = append(findings, scanSecretFindings(input, "js-secret-scan", scriptURL, body)...)
	}
	return strings.Join(rawParts, "\n---\n"), findings
}

func fetchText(ctx context.Context, client HTTPDoer, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "nox/0.1 js-secret-scan")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body), nil
}

func scriptURLs(target models.Target, html string) []string {
	matches := scriptSrcPattern.FindAllStringSubmatch(html, -1)
	limit := min(len(matches), 10)
	urls := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		if resolved := resolveEndpoint(target, matches[i][1]); resolved != "" {
			urls = append(urls, resolved)
		}
	}
	return urls
}

func scanSecretFindings(input AdapterInput, toolID, sourceURL, raw string) []models.Finding {
	seen := map[string]bool{}
	var findings []models.Finding
	for _, pattern := range secretPatterns {
		for _, match := range pattern.regex.FindAllString(raw, -1) {
			key := pattern.name + ":" + match
			if seen[key] {
				continue
			}
			seen[key] = true
			finding := externalFinding(input, toolID, models.FindingTypeExposure, pattern.severity, "Potential secret exposed in JavaScript", fmt.Sprintf("%s pattern matched in %s.", pattern.name, sourceURL), "Confirm whether the matched value is a live secret, then revoke and remove it from public assets.", raw, map[string]any{"source_url": sourceURL, "pattern": pattern.name, "match": match}, []string{toolID, "secret", "javascript", "exposed-secret"})
			finding.URL = sourceURL
			findings = append(findings, finding)
		}
	}
	return findings
}

func parseCORSFindings(input AdapterInput, rawURL, origin string, headers map[string]string, raw string) []models.Finding {
	allowOrigin := strings.TrimSpace(headers["access-control-allow-origin"])
	allowCredentials := strings.EqualFold(strings.TrimSpace(headers["access-control-allow-credentials"]), "true")
	if allowOrigin == "" {
		return nil
	}
	var severity models.Severity
	var title string
	var tags []string
	switch {
	case allowOrigin == "*" && allowCredentials:
		severity = models.SeverityMedium
		title = "CORS wildcard origin allows credentials"
		tags = []string{"cors", "cors-wildcard", "cors-credentials", "cors-wildcard-credentials"}
	case allowOrigin == "*":
		severity = models.SeverityLow
		title = "CORS wildcard origin allowed"
		tags = []string{"cors", "cors-wildcard"}
	case strings.EqualFold(allowOrigin, origin) && allowCredentials:
		severity = models.SeverityMedium
		title = "CORS reflects arbitrary origin with credentials"
		tags = []string{"cors", "cors-reflected-origin", "cors-credentials"}
	default:
		return nil
	}
	finding := externalFinding(input, "cors-check", models.FindingTypeMisconfiguration, severity, title, "The application returned permissive CORS headers for an untrusted Origin.", "Restrict Access-Control-Allow-Origin to trusted origins and avoid credentials unless required.", raw, map[string]any{"url": rawURL, "request_origin": origin, "headers": headers}, tags)
	finding.URL = rawURL
	return []models.Finding{finding}
}

func parseCloudBucketFindings(input AdapterInput, rawURL string, statusCode int, raw string) []models.Finding {
	if statusCode != http.StatusOK {
		return nil
	}
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "listbucketresult") && !strings.Contains(lower, "bucket") && !strings.Contains(lower, "storage") {
		return nil
	}
	finding := externalFinding(input, "cloud-bucket-check", models.FindingTypeExposure, models.SeverityHigh, "Public cloud storage bucket exposed", "The scoped cloud storage endpoint returned public bucket listing metadata.", "Disable public bucket listing unless explicitly intended and review object permissions.", raw, map[string]any{"url": rawURL, "status_code": statusCode}, []string{"cloud-bucket", "s3", "gcs", "public-bucket"})
	finding.URL = rawURL
	return []models.Finding{finding}
}

var parameterNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\-]{0,63}$`)
var parameterPattern = regexp.MustCompile(`(?i)(?:param(?:eter)?|found)\s*[:=]\s*([A-Za-z_][A-Za-z0-9_\-]{0,63})`)
var endpointPattern = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|//[^\s"'<>]+|/[A-Za-z0-9][A-Za-z0-9_\-./?=&%]+)`)
var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

var secretPatterns = []struct {
	name     string
	regex    *regexp.Regexp
	severity models.Severity
}{
	{name: "AWS access key", regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), severity: models.SeverityHigh},
	{name: "Google API key", regex: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), severity: models.SeverityHigh},
	{name: "generic API secret", regex: regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{12,}["']`), severity: models.SeverityMedium},
}
