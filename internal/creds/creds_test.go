package creds

import (
	"context"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestRunRecordsRedactedCredentialCandidate(t *testing.T) {
	ctx := context.Background()
	store, session := credentialTestStore(t)
	defer store.Close()
	results, err := Run(ctx, store, session.ID, TestRequest{Mode: "correlate", Username: "admin", Password: "secret"})
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

func credentialTestStore(t *testing.T) (*db.Store, models.Session) {
	t.Helper()
	ctx := context.Background()
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: "https://example.test", InScope: []string{"https://example.test"}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "example.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: time.Now().UTC()}
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
