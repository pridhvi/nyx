package creds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func TestRunRecordsRedactedCredentialCandidate(t *testing.T) {
	ctx := context.Background()
	store, session := credentialTestStore(t)
	defer store.Close()
	results, err := Run(ctx, store, session.ID, TestRequest{Mode: "correlate", Username: "admin", Password: "secret", StoreSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	redacted := RedactAll(results, false)
	if len(redacted) != 1 || redacted[0].Password != "********" {
		t.Fatalf("expected redacted credential, got %#v", redacted)
	}
	raw := RedactAll(results, true)
	if raw[0].Password != "secret" {
		t.Fatalf("expected plaintext only when requested, got %#v", raw)
	}
}

func TestRunHTTPDefaultCheckPersistsConfirmedRedactedCredential(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("username") == "admin" && r.FormValue("password") == "password" {
			fmt.Fprintln(w, "success welcome dashboard")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "invalid")
	}))
	defer server.Close()

	store, session := credentialTestStoreForTarget(t, server.URL)
	defer store.Close()
	results, err := Run(ctx, store, session.ID, TestRequest{Mode: "defaults", URL: server.URL, Username: "admin", Password: "password", Confirm: true, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, result := range results {
		if result.Valid && result.Username == "admin" && result.Password == "********" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected confirmed redacted credential, got %#v", results)
	}
}

func TestRunHTTPDefaultCheckRequiresExplicitCredentials(t *testing.T) {
	ctx := context.Background()
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	store, session := credentialTestStoreForTarget(t, server.URL)
	defer store.Close()
	_, err := Run(ctx, store, session.ID, TestRequest{Mode: "defaults", URL: server.URL, Confirm: true, MaxAttempts: 2})
	if err == nil || !strings.Contains(err.Error(), "explicit username and password") {
		t.Fatalf("expected explicit credential requirement, got %v", err)
	}
	if called {
		t.Fatal("credential check attempted a login without explicit credentials")
	}
}

func credentialTestStore(t *testing.T) (*db.Store, models.Session) {
	return credentialTestStoreForTarget(t, "https://example.test")
}

func credentialTestStoreForTarget(t *testing.T, targetInput string) (*db.Store, models.Session) {
	t.Helper()
	ctx := context.Background()
	host, port, protocol := targetParts(targetInput)
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: targetInput, InScope: []string{targetInput}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: host, Port: port, Protocol: protocol, IsAlive: true, CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return store, session
}

func targetParts(raw string) (string, int, string) {
	req, _ := http.NewRequest(http.MethodGet, raw, nil)
	port := 443
	protocol := "https"
	if req.URL.Scheme == "http" {
		port = 80
		protocol = "http"
	}
	if req.URL.Port() != "" {
		fmt.Sscanf(req.URL.Port(), "%d", &port)
	}
	return req.URL.Hostname(), port, protocol
}
