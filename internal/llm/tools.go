package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

type ToolDefinition struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type ToolRunner struct {
	store Store
}

func NewToolRunner(store Store) ToolRunner {
	return ToolRunner{store: store}
}

func ToolDefinitions() []ToolDefinition {
	return []ToolDefinition{
		objectTool("request_scan", "Request a follow-up scan for an in-scope target. This records a constrained request only; scans still require explicit API or CLI execution.", map[string]any{
			"target": map[string]any{"type": "string"},
			"tool":   map[string]any{"type": "string"},
			"reason": map[string]any{"type": "string"},
		}, []string{"target", "reason"}),
		objectTool("lookup_cve", "Look up a CVE that is already correlated with the current session.", map[string]any{
			"cve_id": map[string]any{"type": "string"},
		}, []string{"cve_id"}),
		objectTool("search_cves_for_technology", "Search persisted session CVE matches for a technology name.", map[string]any{
			"technology": map[string]any{"type": "string"},
		}, []string{"technology"}),
		objectTool("get_session_findings", "Return persisted findings for this session, optionally filtered by severity or tool.", map[string]any{
			"severity": map[string]any{"type": "string"},
			"tool_id":  map[string]any{"type": "string"},
			"type":     map[string]any{"type": "string"},
		}, nil),
	}
}

func objectTool(name, description string, properties map[string]any, required []string) ToolDefinition {
	params := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		params["required"] = required
	}
	return ToolDefinition{
		Type: "function",
		Function: ToolFunction{
			Name:        name,
			Description: description,
			Parameters:  params,
		},
	}
}

func (r ToolRunner) Execute(ctx context.Context, sessionID string, call ChatToolCall) (string, error) {
	switch call.Name {
	case "request_scan":
		return r.requestScan(ctx, sessionID, call.Arguments)
	case "lookup_cve":
		return r.lookupCVE(ctx, sessionID, call.Arguments)
	case "search_cves_for_technology":
		return r.searchCVEsForTechnology(ctx, sessionID, call.Arguments)
	case "get_session_findings":
		return r.getSessionFindings(ctx, sessionID, call.Arguments)
	default:
		return "", fmt.Errorf("unsupported tool %q", call.Name)
	}
}

func (r ToolRunner) requestScan(ctx context.Context, sessionID, args string) (string, error) {
	var input struct {
		Target string `json:"target"`
		Tool   string `json:"tool"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(defaultJSON(args)), &input); err != nil {
		return "", err
	}
	session, err := r.store.GetSession(ctx)
	if err != nil {
		return "", err
	}
	inScope := targetAllowed(input.Target, session)
	result := map[string]any{
		"accepted": false,
		"in_scope": inScope,
		"target":   input.Target,
		"tool":     input.Tool,
		"reason":   input.Reason,
	}
	if inScope {
		result["message"] = "Follow-up scan request recorded in LLM audit trail only; execute scans through the CLI or API."
	} else {
		result["message"] = "Denied because the requested target is outside the current session scope."
	}
	return marshalResult(result)
}

func (r ToolRunner) lookupCVE(ctx context.Context, sessionID, args string) (string, error) {
	var input struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.Unmarshal([]byte(defaultJSON(args)), &input); err != nil {
		return "", err
	}
	matches, err := r.store.ListCVEMatchesBySession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	for _, match := range matches {
		if strings.EqualFold(match.CVEID, input.CVEID) {
			return marshalResult(match)
		}
	}
	return marshalResult(map[string]any{"found": false, "cve_id": input.CVEID})
}

func (r ToolRunner) searchCVEsForTechnology(ctx context.Context, sessionID, args string) (string, error) {
	var input struct {
		Technology string `json:"technology"`
	}
	if err := json.Unmarshal([]byte(defaultJSON(args)), &input); err != nil {
		return "", err
	}
	targets, err := r.store.ListTargets(ctx, sessionID)
	if err != nil {
		return "", err
	}
	technologyIDs := map[string]bool{}
	for _, target := range targets {
		for _, technology := range target.Technologies {
			if strings.Contains(strings.ToLower(technology.Name), strings.ToLower(input.Technology)) {
				technologyIDs[technology.ID] = true
			}
		}
	}
	matches, err := r.store.ListCVEMatchesBySession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	var out []models.CVEMatch
	for _, match := range matches {
		if technologyIDs[match.TechnologyID] {
			out = append(out, match)
		}
	}
	return marshalResult(out)
}

func (r ToolRunner) getSessionFindings(ctx context.Context, sessionID, args string) (string, error) {
	var input db.FindingFilter
	if strings.TrimSpace(args) != "" {
		if err := json.Unmarshal([]byte(args), &input); err != nil {
			return "", err
		}
	}
	findings, err := r.store.ListFindings(ctx, sessionID, input)
	if err != nil {
		return "", err
	}
	for i := range findings {
		truncateFindingEvidence(&findings[i])
	}
	return marshalResult(findings)
}

func targetAllowed(target string, session models.Session) bool {
	targetHost := hostForScopeMatch(target)
	if targetHost == "" {
		return false
	}
	for _, scope := range session.OutOfScope {
		if hostMatchesScope(targetHost, scope) {
			return false
		}
	}
	for _, scope := range append([]string{session.TargetInput}, session.InScope...) {
		if hostMatchesScope(targetHost, scope) {
			return true
		}
	}
	return false
}

func hostMatchesScope(host, scope string) bool {
	scope = strings.TrimSpace(strings.ToLower(scope))
	if scope == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(scope); err == nil {
		addr, addrErr := netip.ParseAddr(host)
		return addrErr == nil && prefix.Contains(addr)
	}
	scopeHost := hostForScopeMatch(scope)
	if scopeHost == "" {
		return false
	}
	return host == scopeHost || strings.HasSuffix(host, "."+scopeHost)
}

func hostForScopeMatch(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil && parsed.Host != "" {
			return cleanHost(parsed.Host)
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return cleanHost(host)
	}
	if strings.Contains(value, "/") {
		parsed, err := url.Parse("scheme://" + value)
		if err == nil && parsed.Host != "" {
			return cleanHost(parsed.Host)
		}
	}
	return cleanHost(value)
}

func cleanHost(host string) string {
	host = strings.Trim(host, "[]")
	if parsed := net.ParseIP(host); parsed != nil {
		return parsed.String()
	}
	return strings.TrimSuffix(host, ".")
}

func defaultJSON(value string) string {
	if strings.TrimSpace(value) == "" {
		return "{}"
	}
	return value
}

func marshalResult(value any) (string, error) {
	out, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
