package burp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

type RESTResult struct {
	Available bool   `json:"available"`
	Action    string `json:"action"`
	Message   string `json:"message"`
	Count     int    `json:"count,omitempty"`
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type issuesXML struct {
	Issues []issueXML `xml:"issue"`
}

type issueXML struct {
	Host       string `xml:"host"`
	Path       string `xml:"path"`
	Location   string `xml:"location"`
	Name       string `xml:"name"`
	Severity   string `xml:"severity"`
	Confidence string `xml:"confidence"`
	IssueType  string `xml:"type"`
	Request    string `xml:"requestresponse>request"`
	Response   string `xml:"requestresponse>response"`
}

func ImportXML(ctx context.Context, store *db.Store, session models.Session, raw []byte) (models.BurpImportResult, error) {
	var parsed issuesXML
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return models.BurpImportResult{}, err
	}
	now := time.Now().UTC()
	var result models.BurpImportResult
	for _, issue := range parsed.Issues {
		host := strings.TrimSpace(issue.Host)
		if host == "" {
			continue
		}
		if !hostInSessionScope(session, host) {
			result.SkippedOutOfScope++
			continue
		}
		target := models.Target{
			ID:           models.NewID(),
			SessionID:    session.ID,
			Host:         strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"),
			Port:         443,
			Protocol:     "https",
			IsAlive:      true,
			DiscoveredBy: "burp-import",
			CreatedAt:    now,
		}
		if strings.HasPrefix(host, "http://") {
			target.Protocol = "http"
			target.Port = 80
		}
		if err := store.InsertTarget(ctx, target); err != nil {
			return result, err
		}
		result.TargetsImported++
		finding := models.Finding{
			ID:          models.NewID(),
			SessionID:   session.ID,
			TargetID:    target.ID,
			ToolID:      "burp",
			Type:        models.FindingTypeVulnerability,
			Severity:    mapSeverity(issue.Severity),
			Confidence:  mapConfidence(issue.Confidence),
			Title:       firstNonEmpty(issue.Name, issue.IssueType, "Burp issue"),
			Description: "Imported from Burp XML.",
			URL:         firstNonEmpty(issue.Location, host+issue.Path),
			EvidenceRaw: truncate(decodeMaybe(issue.Request)+"\n\n"+decodeMaybe(issue.Response), 4000),
			Tags:        []string{"burp"},
			CreatedAt:   now,
		}
		if request, response := decodeMaybe(issue.Request), decodeMaybe(issue.Response); request != "" || response != "" {
			finding.HTTPEvidence = &models.HTTPEvidence{RequestRaw: truncate(request, 8000), ResponseRaw: truncate(response, 8000)}
			result.EvidenceImported++
		}
		if err := store.InsertFinding(ctx, finding); err != nil {
			return result, err
		}
		result.FindingsImported++
	}
	_ = store.UpdateSessionCounts(ctx, session.ID)
	return result, nil
}

func ExportScope(ctx context.Context, store *db.Store, sessionID string) ([]byte, error) {
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><scope>`)
	for _, target := range targets {
		fmt.Fprintf(&buf, `<url>%s://%s:%d</url>`, html.EscapeString(target.Protocol), html.EscapeString(target.Host), target.Port)
	}
	buf.WriteString(`</scope>`)
	return buf.Bytes(), nil
}

func ExportFindings(ctx context.Context, store *db.Store, sessionID string) ([]byte, error) {
	findings, err := store.ListFindings(ctx, sessionID, db.FindingFilter{})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><issues>`)
	for _, finding := range findings {
		fmt.Fprintf(&buf, `<issue><name>%s</name><severity>%s</severity><confidence>Firm</confidence><host>%s</host><path>%s</path><location>%s</location></issue>`,
			html.EscapeString(finding.Title), html.EscapeString(string(finding.Severity)), html.EscapeString(finding.URL), "", html.EscapeString(finding.URL))
	}
	buf.WriteString(`</issues>`)
	return buf.Bytes(), nil
}

func Status(ctx context.Context, config models.BurpConfig, client HTTPDoer) RESTResult {
	if strings.TrimSpace(config.BaseURL) == "" {
		return RESTResult{Available: false, Action: "status", Message: "Burp REST base URL is not configured"}
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := restRequest(ctx, config, http.MethodGet, "/v0.1/scan", nil)
	if err != nil {
		return RESTResult{Available: false, Action: "status", Message: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return RESTResult{Available: false, Action: "status", Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return RESTResult{Available: true, Action: "status", Message: fmt.Sprintf("Burp REST responded with HTTP %d", resp.StatusCode)}
	}
	return RESTResult{Available: false, Action: "status", Message: fmt.Sprintf("Burp REST returned HTTP %d", resp.StatusCode)}
}

func PushScope(ctx context.Context, store *db.Store, sessionID string, config models.BurpConfig, client HTTPDoer) (RESTResult, error) {
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return RESTResult{}, err
	}
	if strings.TrimSpace(config.BaseURL) == "" {
		return RESTResult{Available: false, Action: "push_scope", Message: "Burp REST base URL is not configured"}, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	var urls []string
	for _, target := range targets {
		urls = append(urls, fmt.Sprintf("%s://%s:%d", target.Protocol, target.Host, target.Port))
	}
	body, _ := json.Marshal(map[string]any{"urls": urls})
	req, err := restRequest(ctx, config, http.MethodPost, "/v0.1/scope", bytes.NewReader(body))
	if err != nil {
		return RESTResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return RESTResult{Available: false, Action: "push_scope", Message: err.Error(), Count: len(urls)}, nil
	}
	defer resp.Body.Close()
	return RESTResult{Available: resp.StatusCode >= 200 && resp.StatusCode < 300, Action: "push_scope", Message: fmt.Sprintf("Burp REST returned HTTP %d", resp.StatusCode), Count: len(urls)}, nil
}

func PullIssues(ctx context.Context, store *db.Store, session models.Session, config models.BurpConfig, client HTTPDoer) (models.BurpImportResult, RESTResult, error) {
	if strings.TrimSpace(config.BaseURL) == "" {
		return models.BurpImportResult{}, RESTResult{Available: false, Action: "pull_issues", Message: "Burp REST base URL is not configured"}, nil
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	req, err := restRequest(ctx, config, http.MethodGet, "/v0.1/issues", nil)
	if err != nil {
		return models.BurpImportResult{}, RESTResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return models.BurpImportResult{}, RESTResult{Available: false, Action: "pull_issues", Message: err.Error()}, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return models.BurpImportResult{}, RESTResult{Available: false, Action: "pull_issues", Message: fmt.Sprintf("Burp REST returned HTTP %d", resp.StatusCode)}, nil
	}
	result, err := ImportJSON(ctx, store, session, raw)
	return result, RESTResult{Available: true, Action: "pull_issues", Message: fmt.Sprintf("Imported %d Burp issues", result.FindingsImported), Count: result.FindingsImported}, err
}

func ImportJSON(ctx context.Context, store *db.Store, session models.Session, raw []byte) (models.BurpImportResult, error) {
	var parsed struct {
		Issues []struct {
			Host       string `json:"host"`
			Path       string `json:"path"`
			URL        string `json:"url"`
			Name       string `json:"name"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			Request    string `json:"request"`
			Response   string `json:"response"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return models.BurpImportResult{}, err
	}
	var xmlIssues issuesXML
	for _, issue := range parsed.Issues {
		xmlIssues.Issues = append(xmlIssues.Issues, issueXML{
			Host: issue.Host, Path: issue.Path, Location: issue.URL, Name: issue.Name,
			Severity: issue.Severity, Confidence: issue.Confidence, Request: issue.Request, Response: issue.Response,
		})
	}
	body, _ := xml.Marshal(xmlIssues)
	return ImportXML(ctx, store, session, body)
}

func restRequest(ctx context.Context, config models.BurpConfig, method, endpoint string, body io.Reader) (*http.Request, error) {
	if err := ValidateBaseURL(config.BaseURL, config.AllowedHosts); err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid Burp REST base URL")
	}
	ref, _ := url.Parse(endpoint)
	req, err := http.NewRequestWithContext(ctx, method, base.ResolveReference(ref).String(), body)
	if err != nil {
		return nil, err
	}
	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
		req.Header.Set("X-API-Key", config.APIKey)
	}
	req.Header.Set("User-Agent", "nyx/0.1 burp-bridge")
	return req, nil
}

func mapSeverity(value string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "information", "info":
		return models.SeverityInfo
	default:
		return models.SeverityMedium
	}
}

func hostInSessionScope(session models.Session, rawHost string) bool {
	host := burpScopeHost(rawHost)
	if host == "" {
		return false
	}
	for _, blocked := range session.OutOfScope {
		if scopeEntryMatchesHost(blocked, host) {
			return false
		}
	}
	entries := append(splitScopeEntries(session.TargetInput), session.InScope...)
	for _, allowed := range entries {
		if scopeEntryMatchesHost(allowed, host) {
			return true
		}
	}
	return false
}

func splitScopeEntries(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
}

func scopeEntryMatchesHost(entry, host string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		ip := net.ParseIP(host)
		return ip != nil && cidr.Contains(ip)
	}
	pattern := burpScopeHost(entry)
	if pattern == "" {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, strings.TrimPrefix(pattern, "*"))
	}
	return host == pattern
}

func burpScopeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		raw = parsed.Host
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(strings.ToLower(raw), "[]")
	raw, _, _ = strings.Cut(raw, "/")
	return raw
}

func mapConfidence(value string) float64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "certain":
		return 1
	case "firm":
		return 0.8
	case "tentative":
		return 0.45
	default:
		return 0.6
	}
}

func decodeMaybe(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return string(decoded)
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[truncated]"
}
