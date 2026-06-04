package payload

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/scopehttp"
)

type ValidationOptions struct {
	Confirm bool
	Enabled bool
	Client  interface {
		Do(*http.Request) (*http.Response, error)
	}
}

type ValidationResult struct {
	Payload   models.Payload `json:"payload"`
	Validated bool           `json:"validated"`
	Evidence  string         `json:"evidence"`
	Reason    string         `json:"reason,omitempty"`
}

func Validate(ctx context.Context, store *db.Store, session models.Session, payloadID string, options ValidationOptions) (ValidationResult, error) {
	if !options.Confirm {
		return ValidationResult{}, fmt.Errorf("payload validation requires confirm=true")
	}
	if !options.Enabled {
		return ValidationResult{}, fmt.Errorf("active payload validation is disabled")
	}
	payload, err := store.PayloadByID(ctx, session.ID, payloadID)
	if err != nil {
		return ValidationResult{}, err
	}
	finding, err := store.GetFinding(ctx, session.ID, payload.FindingID)
	if err != nil {
		return ValidationResult{}, err
	}
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return ValidationResult{}, err
	}
	targetURL, err := validationURL(finding, payload)
	if err != nil {
		return ValidationResult{}, err
	}
	if !inScope(targetURL, session, targets) {
		return ValidationResult{}, fmt.Errorf("payload validation URL is outside session scope")
	}
	client := options.Client
	if client == nil {
		scopedClient, err := scopehttp.NewClient(validationScope{session: session, targets: targets}, scopehttp.Options{Timeout: 8 * time.Second})
		if err != nil {
			return ValidationResult{}, err
		}
		client = scopedClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return ValidationResult{}, err
	}
	req.Header.Set("User-Agent", "nyx/0.1 safe-payload-validator")
	resp, err := client.Do(req)
	if err != nil {
		return ValidationResult{}, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	body := string(bodyBytes)
	validated, evidence := validationEvidence(payload, resp.StatusCode, body)
	if evidence == "" {
		evidence = fmt.Sprintf("HTTP %d; marker not observed in limited response", resp.StatusCode)
	}
	if err := store.UpdatePayloadValidation(ctx, session.ID, payload.ID, evidence, validated); err != nil {
		return ValidationResult{}, err
	}
	payload.Validated = validated
	payload.ValidatedResponse = evidence
	return ValidationResult{Payload: payload, Validated: validated, Evidence: evidence}, nil
}

func validationURL(finding models.Finding, payload models.Payload) (string, error) {
	raw := strings.TrimSpace(finding.URL)
	if raw == "" {
		return "", fmt.Errorf("finding has no URL for payload validation")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("finding URL is invalid")
	}
	query := parsed.Query()
	parameter := strings.TrimSpace(finding.Parameter)
	if parameter == "" {
		switch payload.PayloadType {
		case "open_redirect":
			parameter = firstExisting(query, "next", "url", "redirect", "return")
		default:
			parameter = firstExisting(query, "q", "search", "name", "input")
		}
	}
	if parameter == "" {
		parameter = "q"
	}
	query.Set(parameter, payload.Payload)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

type validationScope struct {
	session models.Session
	targets []models.Target
}

func (s validationScope) IsInScope(raw string) (bool, string) {
	if inScope(raw, s.session, s.targets) {
		return true, ""
	}
	return false, "payload validation URL is outside session scope"
}

func validationEvidence(payload models.Payload, status int, body string) (bool, string) {
	lower := strings.ToLower(body)
	switch payload.PayloadType {
	case "xss":
		if strings.Contains(lower, "confirm") || strings.Contains(lower, "nyx") {
			return true, fmt.Sprintf("HTTP %d reflected the XSS marker", status)
		}
	case "ssti":
		if strings.Contains(body, "49") {
			return true, fmt.Sprintf("HTTP %d reflected evaluated SSTI marker 49", status)
		}
	case "xxe":
		if strings.Contains(lower, "nyx") {
			return true, fmt.Sprintf("HTTP %d reflected non-exfiltrating XXE marker", status)
		}
	case "open_redirect":
		if status >= 300 && status < 400 {
			return true, fmt.Sprintf("HTTP %d returned a redirect response", status)
		}
		if strings.Contains(lower, "example.com/nyx-redirect-marker") {
			return true, fmt.Sprintf("HTTP %d reflected redirect marker", status)
		}
	}
	return false, ""
}

func firstExisting(query url.Values, names ...string) string {
	for _, name := range names {
		if _, ok := query[name]; ok {
			return name
		}
	}
	return ""
}

func inScope(raw string, session models.Session, targets []models.Target) bool {
	parsed, err := url.Parse(raw)
	host := ""
	if err == nil {
		host = strings.ToLower(parsed.Hostname())
	}
	if host == "" {
		host = scopeHost(raw)
	}
	if host == "" {
		return false
	}
	for _, scope := range append([]string{session.TargetInput}, session.InScope...) {
		if strings.EqualFold(scopeHost(scope), host) {
			return true
		}
	}
	for _, target := range targets {
		if strings.EqualFold(target.Host, host) || strings.EqualFold(target.IP, host) {
			return true
		}
	}
	return false
}

func scopeHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	raw, _, _ = strings.Cut(raw, "/")
	raw, _, _ = strings.Cut(raw, ":")
	return strings.ToLower(raw)
}
