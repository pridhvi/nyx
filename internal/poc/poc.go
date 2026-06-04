package poc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/models"
)

type RunRequest struct {
	PoCType                 string `json:"poc_type"`
	PayloadID               string `json:"payload_id"`
	Confirm                 bool   `json:"confirm"`
	ActiveValidationEnabled bool   `json:"active_validation_enabled"`
	CallbackBaseURL         string `json:"callback_base_url"`
	Client                  interface {
		Do(*http.Request) (*http.Response, error)
	} `json:"-"`
}

func Run(ctx context.Context, store *db.Store, sessionID, findingID string, req RunRequest) (models.PoCResult, error) {
	if !req.Confirm {
		return models.PoCResult{}, fmt.Errorf("poc run requires confirm=true")
	}
	finding, err := store.GetFinding(ctx, sessionID, findingID)
	if err != nil {
		return models.PoCResult{}, err
	}
	now := time.Now().UTC()
	completed := now
	pocType := strings.TrimSpace(req.PoCType)
	if pocType == "" {
		pocType = inferType(finding)
	}
	result := models.PoCResult{
		ID:              models.NewID(),
		SessionID:       sessionID,
		FindingID:       findingID,
		TargetID:        finding.TargetID,
		PoCType:         pocType,
		Status:          models.PoCStatusInconclusive,
		PayloadID:       strings.TrimSpace(req.PayloadID),
		Evidence:        "Safe PoC request recorded. Automatic active exploitation is disabled for this finding type in the current slice.",
		ImpactNarrative: "Manual validation is required before treating this finding as proven impact.",
		CreatedAt:       now,
		CompletedAt:     &completed,
	}
	text := strings.ToLower(finding.Title + " " + finding.Description)
	if req.ActiveValidationEnabled {
		if evidence, status, code := safeValidate(ctx, store, sessionID, req, finding, pocType); evidence != "" {
			result.Evidence = evidence
			result.Status = status
			result.ResponseCode = code
		}
	} else if strings.Contains(text, "reflected") || strings.Contains(text, "open redirect") {
		result.Evidence = "Finding is eligible for safe manual validation; active validation is disabled."
	}
	if (pocType == "ssrf" || pocType == "redirect" || pocType == "open_redirect") && strings.TrimSpace(req.CallbackBaseURL) != "" {
		token := models.NewID()
		callbackURL := strings.TrimRight(req.CallbackBaseURL, "/") + "/" + token
		result.CanaryToken = token
		result.Evidence += " Callback canary prepared at " + callbackURL + "."
		_ = store.InsertPowerCallback(ctx, models.PowerCallback{
			ID:        models.NewID(),
			SessionID: sessionID,
			FindingID: findingID,
			Provider:  "builtin",
			Token:     token,
			URL:       callbackURL,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	if err := store.InsertPoCResult(ctx, result); err != nil {
		return models.PoCResult{}, err
	}
	return result, nil
}

func safeValidate(ctx context.Context, store *db.Store, sessionID string, req RunRequest, finding models.Finding, pocType string) (string, models.PoCStatus, int) {
	rawURL := strings.TrimSpace(finding.URL)
	if rawURL == "" {
		return "", "", 0
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", 0
	}
	if ok, reason := urlInSessionScope(ctx, store, sessionID, parsed.String()); !ok {
		return fmt.Sprintf("Active validation skipped: finding URL is outside session scope (%s).", reason), models.PoCStatusFailed, 0
	}
	query := parsed.Query()
	switch pocType {
	case "xss":
		query.Set(firstNonEmpty(finding.Parameter, "q"), `"><span>nyx-poc</span>`)
	case "ssti":
		query.Set(firstNonEmpty(finding.Parameter, "q"), "{{7*7}}")
	case "xxe":
		query.Set(firstNonEmpty(finding.Parameter, "q"), `<!DOCTYPE x [<!ENTITY nyx "nyx">]>`)
	case "redirect", "open_redirect":
		query.Set(firstNonEmpty(finding.Parameter, "next"), "https://example.com/nyx-redirect-marker")
	default:
		return "", "", 0
	}
	parsed.RawQuery = query.Encode()
	client := req.Client
	if client == nil {
		client = scopedHTTPClient(ctx, store, sessionID)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", "", 0
	}
	httpReq.Header.Set("User-Agent", "nyx/0.1 safe-poc")
	resp, err := client.Do(httpReq)
	if err != nil {
		return err.Error(), models.PoCStatusFailed, 0
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	body := strings.ToLower(string(bodyBytes))
	switch {
	case pocType == "xss" && strings.Contains(body, "nyx-poc"):
		return fmt.Sprintf("Reflected marker observed with HTTP %d.", resp.StatusCode), models.PoCStatusConfirmed, resp.StatusCode
	case pocType == "ssti" && strings.Contains(string(bodyBytes), "49"):
		return fmt.Sprintf("SSTI arithmetic marker evaluated with HTTP %d.", resp.StatusCode), models.PoCStatusConfirmed, resp.StatusCode
	case (pocType == "redirect" || pocType == "open_redirect") && resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Sprintf("Redirect behavior observed with HTTP %d.", resp.StatusCode), models.PoCStatusConfirmed, resp.StatusCode
	default:
		return fmt.Sprintf("Safe marker request completed with HTTP %d, but confirmation marker was not observed.", resp.StatusCode), models.PoCStatusInconclusive, resp.StatusCode
	}
}

func scopedHTTPClient(ctx context.Context, store *db.Store, sessionID string) *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if ok, _ := urlInSessionScope(ctx, store, sessionID, req.URL.String()); !ok {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func urlInSessionScope(ctx context.Context, store *db.Store, sessionID, rawURL string) (bool, string) {
	session, err := store.GetSession(ctx)
	if err != nil {
		return false, err.Error()
	}
	entries := append([]string{session.TargetInput}, session.InScope...)
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return false, err.Error()
	}
	for _, target := range targets {
		if target.Host == "" {
			continue
		}
		entries = append(entries, target.Host)
		if target.Protocol != "" {
			if target.Port > 0 {
				entries = append(entries, fmt.Sprintf("%s://%s:%d", target.Protocol, target.Host, target.Port))
			}
			entries = append(entries, fmt.Sprintf("%s://%s", target.Protocol, target.Host))
		}
	}
	scope, err := engine.NewScopeChecker(entries, session.OutOfScope)
	if err != nil {
		return false, err.Error()
	}
	return scope.IsInScope(rawURL)
}

func inferType(finding models.Finding) string {
	text := strings.ToLower(finding.Title + " " + finding.Description)
	for _, candidate := range []string{"xss", "sqli", "ssrf", "ssti", "xxe", "redirect"} {
		if strings.Contains(text, candidate) {
			return candidate
		}
	}
	return "manual"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
