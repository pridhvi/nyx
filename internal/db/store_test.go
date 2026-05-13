package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanini/nox/internal/models"
)

func TestMigrationCreatesExpectedTables(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, table := range []string{"sessions", "targets", "findings", "tool_runs", "schema_migrations"} {
		var name string
		err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %s: %v", table, err)
		}
	}
}

func TestCreateListShowDeleteSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Example",
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"https://example.com"},
		CreatedAt:   time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.com", 443, "https")
	record, err := CreateSessionDB(ctx, dir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.DBPath); err != nil {
		t.Fatal(err)
	}

	records, err := ListSessions(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 session, got %d", len(records))
	}
	if records[0].Session.TargetCount != 1 {
		t.Fatalf("expected target count 1, got %d", records[0].Session.TargetCount)
	}

	store, err := OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.GetSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != session.ID || got.TargetInput != session.TargetInput {
		t.Fatalf("unexpected session: %#v", got)
	}
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "example.com" || targets[0].Port != 443 {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	store.Close()

	if err := DeleteSession(ctx, dir, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.DBPath); !os.IsNotExist(err) {
		t.Fatalf("expected deleted db, got err %v", err)
	}
}

func TestListSessionsSkipsNonSessionFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.db"), []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	session := models.Session{
		ID:          models.NewID(),
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "example.org",
		InScope:     []string{"example.org"},
		CreatedAt:   time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.org", 443, "https")
	if _, err := CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	records, err := ListSessions(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Session.ID != session.ID {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func testTarget(sessionID, host string, port int, protocol string) models.Target {
	return models.Target{
		ID:           models.NewID(),
		SessionID:    sessionID,
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		DiscoveredBy: "user",
		CreatedAt:    time.Now().UTC(),
	}
}
