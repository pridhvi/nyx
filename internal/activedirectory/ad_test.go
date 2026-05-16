package activedirectory

import (
	"context"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestRecordEnumRequestRequiresInternalScope(t *testing.T) {
	ctx := context.Background()
	store, publicSession := adTestStore(t, "https://example.test", "example.test")
	defer store.Close()
	if _, err := RecordEnumRequest(ctx, store, publicSession, "example.local", false); err == nil {
		t.Fatal("expected public session to reject AD enum")
	}
	if _, err := RecordEnumRequest(ctx, store, publicSession, "example.local", true); err != nil {
		t.Fatalf("expected explicit override to allow record: %v", err)
	}
}

func TestImportBloodHoundCreatesEntitiesRelationshipsAndArtifact(t *testing.T) {
	ctx := context.Background()
	store, session := adTestStore(t, "http://10.0.0.5", "10.0.0.5")
	defer store.Close()
	raw := []byte(`{"nodes":[{"id":"u1","name":"alice","type":"User","domain":"EXAMPLE"},{"id":"g1","name":"Domain Admins","type":"Group","domain":"EXAMPLE"}],"edges":[{"from":"u1","to":"g1","relation":"MemberOf"}]}`)
	if err := ImportBloodHound(ctx, store, session.ID, raw); err != nil {
		t.Fatal(err)
	}
	entities, err := store.ListADEntities(ctx, session.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	relationships, err := store.ListADRelationships(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.ListADArtifacts(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 2 || len(relationships) != 1 || len(artifacts) != 1 {
		t.Fatalf("unexpected import result entities=%#v relationships=%#v artifacts=%#v", entities, relationships, artifacts)
	}
}

func adTestStore(t *testing.T, targetInput, host string) (*db.Store, models.Session) {
	t.Helper()
	ctx := context.Background()
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: targetInput, InScope: []string{targetInput}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: host, Port: 80, Protocol: "http", IsAlive: true, CreatedAt: time.Now().UTC()}
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
