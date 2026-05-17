package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/pridhvi/nox/internal/models"
)

func TestScanContextAppliesAuthAndSeedRoutes(t *testing.T) {
	input := testExternalInput()
	input.Scope = fakeScope{allowed: map[string]bool{"example.com": true}}
	input.Session.TargetInput = "https://example.com"
	input.Session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"route_seeds":        []any{"/search?q=nox", "https://example.com/profile?id=1", "https://evil.test/nope?q=1"},
			"auth_headers":       map[string]any{"Authorization": "Bearer test-token"},
			"auth_cookie_header": "session=abc",
		},
	}

	req, err := newHTTPRequestWithAuth(context.Background(), input, http.MethodGet, "https://example.com/search", nil, "nox-test")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("expected auth header to be applied, got %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "session=abc" {
		t.Fatalf("expected cookie header to be applied, got %q", got)
	}
	if got := vulnerabilityTargetURL(input); got != "https://example.com/search?q=nox" {
		t.Fatalf("expected query seed to become vulnerability target, got %q", got)
	}
	paths := seededPathValues(input)
	if len(paths) != 2 || paths[0] != "search?q=nox" || paths[1] != "profile?id=1" {
		t.Fatalf("expected only in-scope seed paths, got %#v", paths)
	}
	args := authCommandArgs(input, "ffuf")
	if len(args) != 4 || args[0] != "-H" || args[1] != "Authorization: Bearer test-token" || args[2] != "-H" || args[3] != "Cookie: session=abc" {
		t.Fatalf("expected ffuf auth headers, got %#v", args)
	}
	redacted := redactCommandArgs(args)
	if redacted[1] != "********" || redacted[3] != "********" {
		t.Fatalf("expected auth command args to redact persisted values, got %#v", redacted)
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
