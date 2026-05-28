package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/pridhvi/nyx/internal/models"
)

func TestScanContextAppliesAuthAndSeedRoutes(t *testing.T) {
	input := testExternalInput()
	input.Scope = fakeScope{allowed: map[string]bool{"example.com": true}}
	input.Session.TargetInput = "https://example.com"
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"route_seeds":        []any{"/search?q=nyx", "https://example.com/profile?id=1", "https://evil.test/nope?q=1"},
			"auth_headers":       map[string]any{"Authorization": "Bearer test-token"},
			"auth_cookie_header": "session=abc",
		},
	}

	req, err := newHTTPRequestWithAuth(context.Background(), input, http.MethodGet, "https://example.com/search", nil, "nyx-test")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("expected auth header to be applied, got %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "session=abc" {
		t.Fatalf("expected cookie header to be applied, got %q", got)
	}
	if got := vulnerabilityTargetURL(input); got != "https://example.com/search?q=nyx" {
		t.Fatalf("expected query seed to become vulnerability target, got %q", got)
	}
	paths := seededPathValues(input)
	if len(paths) != 2 || paths[0] != "search?q=nyx" || paths[1] != "profile?id=1" {
		t.Fatalf("expected only in-scope seed paths, got %#v", paths)
	}
	args, cleanup, err := authFileCommandArgs(input, "ffuf", "https://example.com/FUZZ")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if strings.Contains(strings.Join(args, " "), "test-token") || strings.Contains(strings.Join(args, " "), "session=abc") {
		t.Fatalf("auth file args must not expose secrets, got %#v", args)
	}
	if len(args) != 4 || args[0] != "-request" || args[2] != "-request-proto" || args[3] != "https" {
		t.Fatalf("expected ffuf auth request file args, got %#v", args)
	}
	body, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Authorization: Bearer test-token") || !strings.Contains(string(body), "Cookie: session=abc") {
		t.Fatalf("expected auth request file to contain headers, got %s", string(body))
	}

	sqlmapArgs, sqlmapCleanup, err := authFileCommandArgs(input, "sqlmap", "https://example.com/search?q=nyx")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlmapCleanup()
	if strings.Contains(strings.Join(sqlmapArgs, " "), "test-token") || strings.Contains(strings.Join(sqlmapArgs, " "), "session=abc") {
		t.Fatalf("sqlmap auth file args must not expose secrets, got %#v", sqlmapArgs)
	}
	if len(sqlmapArgs) != 3 || sqlmapArgs[0] != "-r" || sqlmapArgs[2] != "--force-ssl" {
		t.Fatalf("expected sqlmap request file args, got %#v", sqlmapArgs)
	}
	sqlmapBody, err := os.ReadFile(sqlmapArgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sqlmapBody), "GET /search?q=nyx HTTP/1.1") || !strings.Contains(string(sqlmapBody), "Authorization: Bearer test-token") {
		t.Fatalf("expected sqlmap request file to contain request and headers, got %s", string(sqlmapBody))
	}

	dalfoxArgs, dalfoxCleanup, err := authFileCommandArgs(input, "dalfox", "https://example.com/search?q=nyx")
	if err != nil {
		t.Fatal(err)
	}
	defer dalfoxCleanup()
	if strings.Contains(strings.Join(dalfoxArgs, " "), "test-token") || strings.Contains(strings.Join(dalfoxArgs, " "), "session=abc") {
		t.Fatalf("dalfox config args must not expose secrets, got %#v", dalfoxArgs)
	}
	if len(dalfoxArgs) != 2 || dalfoxArgs[0] != "--config" {
		t.Fatalf("expected dalfox config args, got %#v", dalfoxArgs)
	}
	dalfoxConfig, err := os.ReadFile(dalfoxArgs[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dalfoxConfig), "Bearer test-token") || !strings.Contains(string(dalfoxConfig), "session=abc") {
		t.Fatalf("expected dalfox config to contain auth material, got %s", string(dalfoxConfig))
	}
}

func TestScanContextAppliesSecondaryAuth(t *testing.T) {
	input := authTestInput(t, "https://example.com")
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"secondary_auth_headers":       map[string]any{"Authorization": "Bearer secondary"},
			"secondary_auth_cookie_header": "session=secondary",
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/account", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !applySecondaryAuthToRequest(input, req) {
		t.Fatal("expected secondary auth to be configured")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secondary" {
		t.Fatalf("expected secondary Authorization header, got %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "session=secondary" {
		t.Fatalf("expected secondary Cookie header, got %q", got)
	}
}

func TestResolveSessionAuthFormProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form><input name="csrf" value="token-1"></form>`))
				return
			}
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("csrf") != "token-1" || r.Form.Get("user") != "alice" || r.Form.Get("pass") != "secret" {
					http.Error(w, "bad login", http.StatusUnauthorized)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
				_, _ = w.Write([]byte("Welcome alice"))
				return
			}
		case "/account":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "ok" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Account"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	input := authTestInput(t, server.URL)
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"auth_profile": map[string]any{
				"type":                "form",
				"login_url":           "/login",
				"username":            "alice",
				"password":            "secret",
				"username_field":      "user",
				"password_field":      "pass",
				"csrf_field":          "csrf",
				"validation_url":      "/account",
				"validation_contains": "Account",
			},
		},
	}
	result, err := ResolveSessionAuth(context.Background(), input.Session, input.Target, input.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied {
		t.Fatal("expected auth profile to be applied")
	}
	input.Session = result.Session
	req, err := newHTTPRequestWithAuth(context.Background(), input, http.MethodGet, server.URL+"/account", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Cookie"); got != "session=ok" {
		t.Fatalf("expected resolved session cookie, got %q", got)
	}
}

func TestResolveSessionAuthFormProfilePostLoginSetupPersistsCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.php":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form><input name="user_token" value="login-token"></form>`))
				return
			}
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("user_token") != "login-token" || r.Form.Get("username") != "admin" || r.Form.Get("password") != "password" {
					http.Error(w, "bad login", http.StatusUnauthorized)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "session-ok", Path: "/"})
				_, _ = w.Write([]byte("Welcome"))
				return
			}
		case "/security.php":
			if _, err := r.Cookie("PHPSESSID"); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form><input name="user_token" value="security-token"></form>`))
				return
			}
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("user_token") != "security-token" || r.Form.Get("security") != "low" {
					http.Error(w, "bad security setup", http.StatusUnauthorized)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "security", Value: "low", Path: "/"})
				_, _ = w.Write([]byte("Security level set"))
				return
			}
		case "/index.php":
			sessionCookie, sessionErr := r.Cookie("PHPSESSID")
			securityCookie, securityErr := r.Cookie("security")
			if sessionErr != nil || securityErr != nil || sessionCookie.Value != "session-ok" || securityCookie.Value != "low" {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Welcome to DVWA. Logout"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	input := authTestInput(t, server.URL)
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"auth_profile": map[string]any{
				"type":                "form",
				"login_url":           "/login.php",
				"username":            "admin",
				"password":            "password",
				"username_field":      "username",
				"password_field":      "password",
				"csrf_field":          "user_token",
				"validation_url":      "/index.php",
				"validation_contains": "Logout",
				"post_login_setup": []any{
					map[string]any{
						"method":     "POST",
						"path":       "/security.php",
						"csrf_field": "user_token",
						"form": map[string]any{
							"security":      "low",
							"seclev_submit": "Submit",
						},
					},
				},
			},
		},
	}
	result, err := ResolveSessionAuth(context.Background(), input.Session, input.Target, input.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied {
		t.Fatal("expected auth profile to be applied")
	}
	input.Session = result.Session
	req, err := newHTTPRequestWithAuth(context.Background(), input, http.MethodGet, server.URL+"/index.php", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := req.Header.Get("Cookie")
	if !strings.Contains(cookieHeader, "PHPSESSID=session-ok") || !strings.Contains(cookieHeader, "security=low") {
		t.Fatalf("expected resolved login and security cookies, got %q", cookieHeader)
	}

	profile := input.Session.ToolParameters[models.SessionScanOptionsKey]["auth_profile"].(map[string]any)
	profile["validation_contains"] = "Not present"
	if _, err := ResolveSessionAuth(context.Background(), input.Session, input.Target, input.Scope); err == nil || !strings.Contains(err.Error(), "expected marker") {
		t.Fatalf("expected validation marker failure, got %v", err)
	}
}

func TestResolveSessionAuthJSONLoginProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authentication":{"token":"jwt-token"}}`))
	}))
	defer server.Close()

	input := authTestInput(t, server.URL)
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"auth_profile": map[string]any{
				"type":               "json_login",
				"login_url":          "/login",
				"username":           "alice@example.test",
				"password":           "secret",
				"token_json_path":    "authentication.token",
				"auth_header":        "Authorization",
				"auth_header_prefix": "Bearer ",
			},
		},
	}
	result, err := ResolveSessionAuth(context.Background(), input.Session, input.Target, input.Scope)
	if err != nil {
		t.Fatal(err)
	}
	input.Session = result.Session
	req, err := newHTTPRequestWithAuth(context.Background(), input, http.MethodGet, server.URL+"/api", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer jwt-token" {
		t.Fatalf("expected resolved auth header, got %q", got)
	}
}

func authTestInput(t *testing.T, rawURL string) AdapterInput {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(parsed.Port())
	session := models.Session{ID: "session-auth", Mode: models.ScanModeActive, TargetInput: rawURL}
	return AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target: models.Target{
			ID:        "target-auth",
			SessionID: session.ID,
			Host:      parsed.Hostname(),
			Port:      port,
			Protocol:  parsed.Scheme,
			IsAlive:   true,
		},
		Scope: fakeScope{allowed: map[string]bool{parsed.Hostname(): true}},
	}
}
