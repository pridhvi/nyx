package adapters

import (
	"context"
	"net/http"
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
