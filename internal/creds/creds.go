package creds

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
)

type TestRequest struct {
	Mode        string   `json:"mode"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Usernames   []string `json:"usernames"`
	Passwords   []string `json:"passwords"`
	Service     string   `json:"service"`
	URL         string   `json:"url"`
	Confirm     bool     `json:"confirm"`
	MaxAttempts int      `json:"max_attempts"`
	DelayMS     int      `json:"delay_ms"`
	StoreSecret bool     `json:"store_secret"`
	Client      interface {
		Do(*http.Request) (*http.Response, error)
	} `json:"-"`
}

func Run(ctx context.Context, store *db.Store, sessionID string, req TestRequest) ([]models.CredentialFinding, error) {
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "correlate"
	}
	if req.MaxAttempts <= 0 {
		req.MaxAttempts = 3
	}
	if req.Service == "" {
		req.Service = "web"
	}
	if strings.TrimSpace(req.URL) != "" && req.Confirm {
		if err := runHTTPChecks(ctx, store, sessionID, mode, req); err != nil {
			return nil, err
		}
		return store.ListCredentialFindings(ctx, sessionID, db.CredentialFilter{})
	}
	now := time.Now().UTC()
	credential := models.CredentialFinding{
		ID:             models.NewID(),
		SessionID:      sessionID,
		CredentialType: mode,
		Username:       strings.TrimSpace(req.Username),
		Password:       storedPassword(strings.TrimSpace(req.Password), req.StoreSecret),
		Service:        req.Service,
		URL:            strings.TrimSpace(req.URL),
		Valid:          false,
		Evidence:       "Credential test request recorded. Automated login attempts are intentionally disabled unless a fixture-safe adapter is selected.",
		CreatedAt:      now,
	}
	if credential.Username == "" && credential.Password == "" {
		credential.Username = "candidate"
		credential.Password = "********"
		credential.Evidence = "No explicit credential supplied; recorded a redacted candidate for operator review."
	}
	if err := store.InsertCredentialFinding(ctx, credential); err != nil {
		return nil, err
	}
	return store.ListCredentialFindings(ctx, sessionID, db.CredentialFilter{})
}

func runHTTPChecks(ctx context.Context, store *db.Store, sessionID, mode string, req TestRequest) error {
	users, passwords := credentialCandidates(req)
	if len(users) == 0 || len(passwords) == 0 {
		return fmt.Errorf("active credential checks require at least one explicit username and password")
	}
	session, err := store.GetSession(ctx)
	if err != nil {
		return err
	}
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return err
	}
	if !urlInScope(req.URL, session, targets) {
		return fmt.Errorf("credential test URL is outside session scope")
	}
	client := req.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	attemptsByUser := map[string]int{}
	now := time.Now().UTC()
	for _, username := range users {
		for _, password := range passwords {
			if attemptsByUser[username] >= req.MaxAttempts {
				break
			}
			attemptsByUser[username]++
			valid, lockout, evidence := tryCredential(ctx, client, req.URL, username, password)
			record := models.CredentialFinding{
				ID:              models.NewID(),
				SessionID:       sessionID,
				CredentialType:  mode,
				Username:        username,
				Password:        storedPassword(password, req.StoreSecret),
				Service:         req.Service,
				URL:             strings.TrimSpace(req.URL),
				Valid:           valid,
				LockoutDetected: lockout,
				Evidence:        evidence,
				CreatedAt:       now,
			}
			if err := store.InsertCredentialFinding(ctx, record); err != nil {
				return err
			}
			if lockout {
				return nil
			}
			if req.DelayMS > 0 {
				timer := time.NewTimer(time.Duration(req.DelayMS) * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
	}
	return nil
}

func credentialCandidates(req TestRequest) ([]string, []string) {
	users := compact(req.Usernames)
	passwords := compact(req.Passwords)
	if req.Username != "" {
		users = append([]string{req.Username}, users...)
	}
	if req.Password != "" {
		passwords = append([]string{req.Password}, passwords...)
	}
	return dedupe(users), dedupe(passwords)
}

func tryCredential(ctx context.Context, client interface {
	Do(*http.Request) (*http.Response, error)
}, rawURL, username, password string) (bool, bool, string) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, false, err.Error()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "nyx/0.1 credential-check")
	resp, err := client.Do(req)
	if err != nil {
		return false, false, err.Error()
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	body := strings.ToLower(string(bodyBytes))
	switch {
	case resp.StatusCode == http.StatusLocked || strings.Contains(body, "locked") || strings.Contains(body, "lockout"):
		return false, true, fmt.Sprintf("lockout indicator observed with HTTP %d", resp.StatusCode)
	case resp.StatusCode >= 200 && resp.StatusCode < 400 && (strings.Contains(body, "welcome") || strings.Contains(body, "dashboard") || strings.Contains(body, "success") || strings.Contains(body, "token")):
		return true, false, fmt.Sprintf("success marker observed with HTTP %d", resp.StatusCode)
	default:
		return false, false, fmt.Sprintf("invalid credential response HTTP %d", resp.StatusCode)
	}
}

func storedPassword(password string, storeSecret bool) string {
	if password == "" || storeSecret {
		return password
	}
	return "********"
}

func compact(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func urlInScope(raw string, session models.Session, targets []models.Target) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
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

func RedactAll(credentials []models.CredentialFinding, plaintext bool) []models.CredentialFinding {
	if plaintext {
		return credentials
	}
	out := make([]models.CredentialFinding, 0, len(credentials))
	for _, credential := range credentials {
		out = append(out, credential.Redacted())
	}
	return out
}
