package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type WhatWeb struct{}

func NewWhatWeb() WhatWeb                         { return WhatWeb{} }
func (WhatWeb) ID() string                        { return "whatweb" }
func (WhatWeb) Name() string                      { return "WhatWeb" }
func (WhatWeb) Phase() Phase                      { return PhaseFingerprint }
func (WhatWeb) DependsOn() []string               { return []string{"http-probe"} }
func (WhatWeb) ShouldRun(input AdapterInput) bool { return liveHTTP(input) }
func (a WhatWeb) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"--log-json=-", "--no-errors", rawURL}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 90*time.Second, "whatweb", args...)
	technologies, findings := parseWhatWebOutput(input, result.Stdout)
	return AdapterOutput{Technologies: technologies, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type NucleiTech struct{}

func NewNucleiTech() NucleiTech                      { return NucleiTech{} }
func (NucleiTech) ID() string                        { return "nuclei-tech" }
func (NucleiTech) Name() string                      { return "Nuclei Technology Templates" }
func (NucleiTech) Phase() Phase                      { return PhaseFingerprint }
func (NucleiTech) DependsOn() []string               { return []string{"http-probe"} }
func (NucleiTech) ShouldRun(input AdapterInput) bool { return liveHTTP(input) }
func (a NucleiTech) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"-silent", "-jsonl", "-tags", "tech", "-u", rawURL}
	if templates := toolParamString(input, "templates"); templates != "" {
		args = append(args, "-templates", templates)
	}
	if severity := toolParamString(input, "severity"); severity != "" {
		args = append(args, "-severity", severity)
	}
	args = append(args, toolParamStringList(input, "extra_args")...)
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, commandTimeout(input, 120*time.Second), "nuclei", args...)
	technologies, findings := parseNucleiTechOutput(input, result.Stdout)
	return AdapterOutput{Technologies: technologies, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type TestSSL struct{}

func NewTestSSL() TestSSL           { return TestSSL{} }
func (TestSSL) ID() string          { return "testssl" }
func (TestSSL) Name() string        { return "testssl.sh" }
func (TestSSL) Phase() Phase        { return PhaseFingerprint }
func (TestSSL) DependsOn() []string { return []string{"http-probe"} }
func (TestSSL) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.IsAlive && input.Target.Protocol == "https"
}
func (a TestSSL) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"--jsonfile-pretty", "/dev/stdout", "--warnings", "batch", rawURL}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 180*time.Second, "testssl.sh", args...)
	findings := parseTestSSLOutput(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type GraphQLIntrospection struct{}

func NewGraphQLIntrospection() GraphQLIntrospection            { return GraphQLIntrospection{} }
func (GraphQLIntrospection) ID() string                        { return "graphql-introspection" }
func (GraphQLIntrospection) Name() string                      { return "GraphQL Introspection" }
func (GraphQLIntrospection) Phase() Phase                      { return PhaseFingerprint }
func (GraphQLIntrospection) DependsOn() []string               { return []string{"http-probe"} }
func (GraphQLIntrospection) ShouldRun(input AdapterInput) bool { return liveHTTP(input) }
func (a GraphQLIntrospection) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	endpoint := joinTargetPath(input.Target, "/graphql")
	args := []string{endpoint}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	body := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }"}`
	req, err := newHTTPRequestWithAuth(ctx, input, http.MethodPost, endpoint, strings.NewReader(body), "nox/0.1 graphql-introspection")
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	findings := parseGraphQLIntrospection(input, endpoint, resp.StatusCode, string(respBody))
	run.RawStdout = string(respBody)
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

type OpenAPIDiscovery struct{}

func NewOpenAPIDiscovery() OpenAPIDiscovery                { return OpenAPIDiscovery{} }
func (OpenAPIDiscovery) ID() string                        { return "openapi-discovery" }
func (OpenAPIDiscovery) Name() string                      { return "OpenAPI Discovery" }
func (OpenAPIDiscovery) Phase() Phase                      { return PhaseFingerprint }
func (OpenAPIDiscovery) DependsOn() []string               { return []string{"http-probe"} }
func (OpenAPIDiscovery) ShouldRun(input AdapterInput) bool { return liveHTTP(input) }
func (a OpenAPIDiscovery) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	paths := []string{"/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json", "/docs/swagger.json"}
	args := append([]string{targetURL(input.Target)}, paths...)
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	var raw []string
	var findings []models.Finding
	for _, candidate := range paths {
		endpoint := joinTargetPath(input.Target, candidate)
		req, err := newHTTPRequestWithAuth(ctx, input, http.MethodGet, endpoint, nil, "nox/0.1 openapi-discovery")
		if err != nil {
			raw = append(raw, fmt.Sprintf("%s error: %s", endpoint, err))
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			raw = append(raw, fmt.Sprintf("%s error: %s", endpoint, err))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		raw = append(raw, fmt.Sprintf("%s status=%d body=%s", endpoint, resp.StatusCode, string(body)))
		findings = append(findings, parseOpenAPIDocument(input, endpoint, resp.StatusCode, string(body))...)
	}
	run.RawStdout = strings.Join(raw, "\n")
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

type WPScan struct{}

func NewWPScan() WPScan                          { return WPScan{} }
func (WPScan) ID() string                        { return "wpscan" }
func (WPScan) Name() string                      { return "WPScan" }
func (WPScan) Phase() Phase                      { return PhaseFingerprint }
func (WPScan) DependsOn() []string               { return []string{"http-probe"} }
func (WPScan) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a WPScan) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"--url", rawURL, "--format", "json", "--no-banner", "--disable-tls-checks"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 180*time.Second, "wpscan", args...)
	technologies, findings := parseWPScanOutput(input, result.Stdout)
	return AdapterOutput{Technologies: technologies, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type Droopescan struct{}

func NewDroopescan() Droopescan                      { return Droopescan{} }
func (Droopescan) ID() string                        { return "droopescan" }
func (Droopescan) Name() string                      { return "droopescan" }
func (Droopescan) Phase() Phase                      { return PhaseFingerprint }
func (Droopescan) DependsOn() []string               { return []string{"http-probe"} }
func (Droopescan) ShouldRun(input AdapterInput) bool { return activeOnly(input) && liveHTTP(input) }
func (a Droopescan) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	rawURL := targetURL(input.Target)
	args := []string{"scan", "drupal", "-u", rawURL, "--json"}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 120*time.Second, "droopescan", args...)
	technologies, findings := parseDroopescanOutput(input, result.Stdout)
	return AdapterOutput{Technologies: technologies, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

func liveHTTP(input AdapterInput) bool {
	return input.Target.IsAlive && (input.Target.Protocol == "http" || input.Target.Protocol == "https")
}

func parseWhatWebOutput(input AdapterInput, raw string) ([]models.Technology, []models.Finding) {
	var records []map[string]any
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		for _, line := range strings.Split(raw, "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &record) == nil {
				records = append(records, record)
			}
		}
	}
	seen := map[string]bool{}
	var technologies []models.Technology
	for _, record := range records {
		plugins, _ := record["plugins"].(map[string]any)
		for name, rawPlugin := range plugins {
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			version := pluginFirstString(rawPlugin, "version")
			technologies = append(technologies, technology(input, name, version, "web", 0.75, "whatweb"))
			seen[strings.ToLower(name)] = true
		}
	}
	return technologies, nil
}

func parseNucleiTechOutput(input AdapterInput, raw string) ([]models.Technology, []models.Finding) {
	seen := map[string]bool{}
	var technologies []models.Technology
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record nucleiRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		name := firstNonEmpty(record.Info.Name, record.TemplateID)
		if name != "" && !seen[strings.ToLower(name)] {
			technologies = append(technologies, technology(input, name, "", "web", 0.7, "nuclei-tech"))
			seen[strings.ToLower(name)] = true
		}
		findings = append(findings, externalFinding(input, "nuclei-tech", models.FindingTypeInfo, nucleiSeverity(record.Info.Severity), "Technology fingerprint matched", fmt.Sprintf("Nuclei technology template matched %s.", name), "Review detected technology and version before CVE correlation.", raw, map[string]any{"template_id": record.TemplateID, "name": name, "matched_at": record.MatchedAt}, []string{"nuclei", "technology"}))
	}
	return technologies, findings
}

type nucleiRecord struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func parseTestSSLOutput(input AdapterInput, raw string) []models.Finding {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return parseTestSSLText(input, raw)
	}
	var findings []models.Finding
	for _, row := range rows {
		id := stringField(row, "id")
		severity := strings.ToUpper(firstNonEmpty(stringField(row, "severity"), stringField(row, "severityCode")))
		finding := firstNonEmpty(stringField(row, "finding"), stringField(row, "message"))
		if id == "" || finding == "" || severity == "" || severity == "OK" || severity == "INFO" {
			continue
		}
		findings = append(findings, externalFinding(input, "testssl", models.FindingTypeMisconfiguration, tlsSeverity(severity), "TLS issue detected", finding, "Review TLS protocol, cipher, and certificate configuration.", raw, row, []string{"testssl", "tls"}))
	}
	return findings
}

func parseTestSSLText(input AdapterInput, raw string) []models.Finding {
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if trimmed == "" || !(strings.Contains(upper, "WARN") || strings.Contains(upper, "LOW") || strings.Contains(upper, "MEDIUM") || strings.Contains(upper, "HIGH") || strings.Contains(upper, "CRITICAL")) {
			continue
		}
		findings = append(findings, externalFinding(input, "testssl", models.FindingTypeMisconfiguration, tlsSeverity(upper), "TLS issue detected", trimmed, "Review TLS protocol, cipher, and certificate configuration.", raw, map[string]any{"line": trimmed}, []string{"testssl", "tls"}))
	}
	return findings
}

func parseGraphQLIntrospection(input AdapterInput, endpoint string, statusCode int, raw string) []models.Finding {
	if statusCode < 200 || statusCode >= 300 || !strings.Contains(raw, `"__schema"`) {
		return nil
	}
	return []models.Finding{externalFinding(input, "graphql-introspection", models.FindingTypeExposure, models.SeverityMedium, "GraphQL introspection is exposed", "The GraphQL endpoint returned schema introspection data.", "Disable introspection in production or require authentication for schema access.", raw, map[string]any{"url": endpoint, "status_code": statusCode}, []string{"graphql", "introspection"})}
}

func parseOpenAPIDocument(input AdapterInput, endpoint string, statusCode int, raw string) []models.Finding {
	if statusCode < 200 || statusCode >= 300 {
		return nil
	}
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "openapi") && !strings.Contains(lower, "swagger") {
		return nil
	}
	return []models.Finding{externalFinding(input, "openapi-discovery", models.FindingTypeExposure, models.SeverityLow, "OpenAPI or Swagger document exposed", "An API documentation document was discovered on a common endpoint.", "Confirm the documentation is intended to be public and does not expose sensitive operations.", raw, map[string]any{"url": endpoint, "status_code": statusCode}, []string{"openapi", "swagger", "api-docs"})}
}

func parseWPScanOutput(input AdapterInput, raw string) ([]models.Technology, []models.Finding) {
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return nil, nil
	}
	var technologies []models.Technology
	if version := nestedString(body, "version", "number"); version != "" {
		technologies = append(technologies, technology(input, "WordPress", version, "cms", 0.9, "wpscan"))
	}
	if theme := nestedString(body, "main_theme", "slug"); theme != "" {
		technologies = append(technologies, technology(input, "WordPress theme: "+theme, nestedString(body, "main_theme", "version", "number"), "cms-theme", 0.8, "wpscan"))
	}
	if plugins, ok := body["plugins"].(map[string]any); ok {
		for name, plugin := range plugins {
			technologies = append(technologies, technology(input, "WordPress plugin: "+name, pluginVersion(plugin), "cms-plugin", 0.75, "wpscan"))
		}
	}
	findings := vulnerabilityFindings(input, "wpscan", raw, body)
	return technologies, findings
}

func parseDroopescanOutput(input AdapterInput, raw string) ([]models.Technology, []models.Finding) {
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return nil, nil
	}
	var technologies []models.Technology
	if identified, ok := body["identified"].(string); ok && identified != "" {
		version := firstValueString(body["version"])
		technologies = append(technologies, technology(input, identified, version, "cms", 0.75, "droopescan"))
	}
	for key, rawCMS := range body {
		if strings.HasPrefix(key, "_") {
			continue
		}
		cms := strings.TrimSuffix(key, "_cms")
		if cms == "identified" {
			if text, ok := rawCMS.(string); ok {
				cms = text
			}
		}
		if version := pluginFirstString(rawCMS, "version"); version != "" {
			technologies = append(technologies, technology(input, cms, version, "cms", 0.75, "droopescan"))
		} else if _, ok := rawCMS.(map[string]any); ok {
			technologies = append(technologies, technology(input, cms, "", "cms", 0.6, "droopescan"))
		}
	}
	findings := vulnerabilityFindings(input, "droopescan", raw, body)
	return technologies, findings
}

func vulnerabilityFindings(input AdapterInput, toolID, raw string, body map[string]any) []models.Finding {
	if !strings.Contains(strings.ToLower(raw), "vulnerab") {
		return nil
	}
	return []models.Finding{externalFinding(input, toolID, models.FindingTypeInfo, models.SeverityInfo, "CMS scan reported vulnerability metadata", "The CMS fingerprinting tool returned vulnerability-related metadata.", "Review the raw tool output and confirm affected versions before remediation.", raw, body, []string{toolID, "cms", "vulnerability-metadata"})}
}

func technology(input AdapterInput, name, version, category string, confidence float64, sourceTool string) models.Technology {
	return models.Technology{
		ID:         models.NewID(),
		TargetID:   input.Target.ID,
		Name:       strings.TrimSpace(name),
		Version:    strings.TrimSpace(version),
		Category:   category,
		Confidence: confidence,
		SourceTool: sourceTool,
	}
}

func pluginFirstString(raw any, key string) string {
	object, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	value, ok := object[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && text != "" {
				return text
			}
		}
	case map[string]any:
		return firstNonEmpty(stringField(typed, "number"), stringField(typed, "version"))
	}
	return ""
}

func firstValueString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	case map[string]any:
		return firstNonEmpty(stringField(typed, "number"), stringField(typed, "version"))
	}
	return ""
}

func stringField(object map[string]any, key string) string {
	value, ok := object[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return fmt.Sprintf("%.0f", typed)
	default:
		return ""
	}
}

func nestedString(object map[string]any, keys ...string) string {
	var current any = object
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[key]
	}
	if text, ok := current.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func pluginVersion(raw any) string {
	if value := pluginFirstString(raw, "version"); value != "" {
		return value
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return nestedString(object, "version", "number")
}

func nucleiSeverity(value string) models.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func tlsSeverity(value string) models.Severity {
	upper := strings.ToUpper(value)
	switch {
	case strings.Contains(upper, "CRITICAL"):
		return models.SeverityCritical
	case strings.Contains(upper, "HIGH"):
		return models.SeverityHigh
	case strings.Contains(upper, "MEDIUM"):
		return models.SeverityMedium
	case strings.Contains(upper, "LOW"), strings.Contains(upper, "WARN"):
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func joinTargetPath(target models.Target, suffix string) string {
	base, err := url.Parse(targetURL(target))
	if err != nil {
		return targetURL(target)
	}
	base.Path = path.Join("/", suffix)
	if strings.HasSuffix(suffix, "/") && !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	return base.String()
}
