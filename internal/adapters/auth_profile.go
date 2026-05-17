package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type AuthResolution struct {
	Applied bool
	Message string
	Session models.Session
}

func HasAuthProfile(session models.Session) bool {
	return len(authProfileMap(session)) > 0
}

func ResolveSessionAuth(ctx context.Context, session models.Session, target models.Target, scope ScopeValidator) (AuthResolution, error) {
	profile := authProfileMap(session)
	if len(profile) == 0 {
		return AuthResolution{Session: session}, nil
	}
	if ok, reason := scope.IsInScope(target.Host); !ok {
		return AuthResolution{Session: session}, fmt.Errorf("auth target rejected by scope: %s", reason)
	}
	kind := strings.ToLower(strings.TrimSpace(mapString(profile, "type")))
	if kind == "" {
		kind = "form"
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return AuthResolution{Session: session}, err
	}
	client := &http.Client{Timeout: 20 * time.Second, Jar: jar}
	var headers map[string]string
	switch kind {
	case "form":
		headers, err = resolveFormAuth(ctx, client, target, scope, profile)
	case "json_login":
		headers, err = resolveJSONLoginAuth(ctx, client, target, scope, profile)
	default:
		return AuthResolution{Session: session}, fmt.Errorf("unsupported auth profile type %q", kind)
	}
	if err != nil {
		return AuthResolution{Session: session}, err
	}
	cookies := cookiesForTarget(jar, target)
	cookieHeader := cookieHeader(cookies)
	if len(headers) == 0 && cookieHeader == "" {
		return AuthResolution{Session: session}, fmt.Errorf("auth profile produced no reusable cookies or headers")
	}
	session.ToolParameters = models.BuildScanToolParameters(session.ToolParameters, nil, "", headers, cookies, cookieHeader, nil)
	return AuthResolution{Applied: true, Message: "auth profile resolved", Session: session}, nil
}

func authProfileMap(session models.Session) map[string]any {
	if session.ToolParameters == nil || session.ToolParameters[models.SessionScanOptionsKey] == nil {
		return nil
	}
	raw := session.ToolParameters[models.SessionScanOptionsKey]["auth_profile"]
	if raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	default:
		return nil
	}
}

func resolveFormAuth(ctx context.Context, client *http.Client, target models.Target, scope ScopeValidator, profile map[string]any) (map[string]string, error) {
	loginURL := normalizeSeedURL(target, firstNonEmptyString(mapString(profile, "login_url"), mapString(profile, "url")))
	if loginURL == "" {
		return nil, fmt.Errorf("auth profile login_url is required")
	}
	if err := scopedURL(scope, loginURL); err != nil {
		return nil, err
	}
	username := mapString(profile, "username")
	password := mapString(profile, "password")
	if username == "" || password == "" {
		return nil, fmt.Errorf("auth profile username and password are required")
	}
	usernameField := firstNonEmptyString(mapString(profile, "username_field"), "username")
	passwordField := firstNonEmptyString(mapString(profile, "password_field"), "password")
	csrfField := mapString(profile, "csrf_field")
	fields := mapStringMap(profile["extra_fields"])
	fields[usernameField] = username
	fields[passwordField] = password
	if csrfField != "" {
		token, err := fetchCSRFToken(ctx, client, loginURL, csrfField)
		if err != nil {
			return nil, err
		}
		fields[csrfField] = token
	}
	status, body, err := postForm(ctx, client, loginURL, fields)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("auth login returned HTTP %d", status)
	}
	if contains := mapString(profile, "success_contains"); contains != "" && !strings.Contains(body, contains) {
		return nil, fmt.Errorf("auth login response did not contain expected marker")
	}
	if err := runPostLoginSteps(ctx, client, target, scope, profile); err != nil {
		return nil, err
	}
	if err := validateAuth(ctx, client, target, scope, profile, nil); err != nil {
		return nil, err
	}
	return nil, nil
}

func resolveJSONLoginAuth(ctx context.Context, client *http.Client, target models.Target, scope ScopeValidator, profile map[string]any) (map[string]string, error) {
	loginURL := normalizeSeedURL(target, firstNonEmptyString(mapString(profile, "login_url"), mapString(profile, "url")))
	if loginURL == "" {
		return nil, fmt.Errorf("auth profile login_url is required")
	}
	if err := scopedURL(scope, loginURL); err != nil {
		return nil, err
	}
	username := mapString(profile, "username")
	password := mapString(profile, "password")
	if username == "" || password == "" {
		return nil, fmt.Errorf("auth profile username and password are required")
	}
	usernameField := firstNonEmptyString(mapString(profile, "username_field"), "email")
	passwordField := firstNonEmptyString(mapString(profile, "password_field"), "password")
	payload := map[string]any{usernameField: username, passwordField: password}
	for key, value := range mapStringMap(profile["extra_fields"]) {
		payload[key] = value
	}
	bodyBytes, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nox/0.1 auth-profile")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("auth login returned HTTP %d", resp.StatusCode)
	}
	tokenPath := mapString(profile, "token_json_path")
	if tokenPath == "" {
		return nil, nil
	}
	token, err := jsonPathString(body, tokenPath)
	if err != nil {
		return nil, err
	}
	headerName := firstNonEmptyString(mapString(profile, "auth_header"), "Authorization")
	prefix := ""
	if profile["auth_header_prefix"] != nil {
		prefix = toString(profile["auth_header_prefix"])
	}
	headers := map[string]string{headerName: prefix + token}
	if err := validateAuth(ctx, client, target, scope, profile, headers); err != nil {
		return nil, err
	}
	return headers, nil
}

func runPostLoginSteps(ctx context.Context, client *http.Client, target models.Target, scope ScopeValidator, profile map[string]any) error {
	steps := mapList(profile["post_login_requests"])
	if len(steps) == 0 {
		steps = mapList(profile["post_login_setup"])
	}
	for _, step := range steps {
		rawURL := normalizeSeedURL(target, firstNonEmptyString(mapString(step, "url"), mapString(step, "path")))
		if rawURL == "" {
			continue
		}
		if err := scopedURL(scope, rawURL); err != nil {
			return err
		}
		fields := mapStringMap(step["form"])
		if csrfField := mapString(step, "csrf_field"); csrfField != "" {
			token, err := fetchCSRFToken(ctx, client, rawURL, csrfField)
			if err != nil {
				return err
			}
			fields[csrfField] = token
		}
		method := strings.ToUpper(firstNonEmptyString(mapString(step, "method"), "POST"))
		if method == http.MethodGet {
			if _, _, err := getText(ctx, client, rawURL); err != nil {
				return err
			}
			continue
		}
		status, _, err := postForm(ctx, client, rawURL, fields)
		if err != nil {
			return err
		}
		if status >= 400 {
			return fmt.Errorf("post-login step returned HTTP %d", status)
		}
	}
	return nil
}

func validateAuth(ctx context.Context, client *http.Client, target models.Target, scope ScopeValidator, profile map[string]any, headers map[string]string) error {
	validateURL := normalizeSeedURL(target, mapString(profile, "validation_url"))
	if validateURL == "" {
		return nil
	}
	if err := scopedURL(scope, validateURL); err != nil {
		return err
	}
	status, body, err := getTextWithHeaders(ctx, client, validateURL, headers)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("auth validation returned HTTP %d", status)
	}
	if contains := mapString(profile, "validation_contains"); contains != "" && !strings.Contains(body, contains) {
		return fmt.Errorf("auth validation response did not contain expected marker")
	}
	return nil
}

func fetchCSRFToken(ctx context.Context, client *http.Client, rawURL, field string) (string, error) {
	_, body, err := getText(ctx, client, rawURL)
	if err != nil {
		return "", err
	}
	token := extractInputValue(body, field)
	if token == "" {
		return "", fmt.Errorf("csrf field %q not found", field)
	}
	return token, nil
}

func getText(ctx context.Context, client *http.Client, rawURL string) (int, string, error) {
	return getTextWithHeaders(ctx, client, rawURL, nil)
}

func getTextWithHeaders(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "nox/0.1 auth-profile")
	for name, value := range headers {
		if strings.TrimSpace(name) != "" && value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body), nil
}

func postForm(ctx context.Context, client *http.Client, rawURL string, fields map[string]string) (int, string, error) {
	form := url.Values{}
	for key, value := range fields {
		form.Set(key, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "nox/0.1 auth-profile")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body), nil
}

func extractInputValue(body, field string) string {
	quoted := regexp.QuoteMeta(field)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?is)<input\b[^>]*\bname=["']` + quoted + `["'][^>]*\bvalue=["']([^"']*)["'][^>]*>`),
		regexp.MustCompile(`(?is)<input\b[^>]*\bvalue=["']([^"']*)["'][^>]*\bname=["']` + quoted + `["'][^>]*>`),
	}
	for _, pattern := range patterns {
		match := pattern.FindStringSubmatch(body)
		if len(match) == 2 {
			return html.UnescapeString(match[1])
		}
	}
	return ""
}

func cookiesForTarget(jar http.CookieJar, target models.Target) map[string]string {
	rawURL := targetURL(target)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, cookie := range jar.Cookies(parsed) {
		if cookie.Name != "" && cookie.Value != "" {
			out[cookie.Name] = cookie.Value
		}
	}
	return out
}

func cookieHeader(cookies map[string]string) string {
	var parts []string
	for _, name := range sortedMapKeys(cookies) {
		if cookies[name] != "" {
			parts = append(parts, name+"="+cookies[name])
		}
	}
	return strings.Join(parts, "; ")
}

func scopedURL(scope ScopeValidator, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid auth URL %q", rawURL)
	}
	if ok, reason := scope.IsInScope(parsed.Hostname()); !ok {
		return fmt.Errorf("auth URL rejected by scope: %s", reason)
	}
	return nil
}

func jsonPathString(body []byte, path string) (string, error) {
	var current any
	if err := json.Unmarshal(body, &current); err != nil {
		return "", err
	}
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return "", fmt.Errorf("token_json_path %q did not resolve to a string", path)
		}
		current = object[part]
	}
	token, ok := current.(string)
	if !ok || token == "" {
		return "", fmt.Errorf("token_json_path %q did not resolve to a string", path)
	}
	return token, nil
}

func mapString(values map[string]any, key string) string {
	if values == nil || values[key] == nil {
		return ""
	}
	return strings.TrimSpace(toString(values[key]))
}

func mapStringMap(value any) map[string]string {
	out := anyStringMap(value)
	if out == nil {
		return map[string]string{}
	}
	return out
}

func mapList(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				out = append(out, object)
			}
		}
		return out
	default:
		return nil
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
