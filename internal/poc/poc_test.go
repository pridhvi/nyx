package poc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestRunRequiresExplicitConfirmation(t *testing.T) {
	ctx := context.Background()
	store, session, finding := pocTestStore(t, "Reflected XSS")
	defer store.Close()
	if _, err := Run(ctx, store, session.ID, finding.ID, RunRequest{}); err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Fatalf("expected confirmation error, got %v", err)
	}
	results, err := store.ListPoCResults(ctx, session.ID, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no persisted result without confirmation, got %#v", results)
	}
}

func TestRunPersistsSafeManualResult(t *testing.T) {
	ctx := context.Background()
	store, session, finding := pocTestStore(t, "Open redirect")
	defer store.Close()
	payload := models.Payload{
		ID:          "payload-1",
		SessionID:   session.ID,
		FindingID:   finding.ID,
		PayloadType: "redirect",
		Payload:     "https://example.net/",
		Context:     "test",
		Confidence:  0.5,
		Rank:        1,
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	result, err := Run(ctx, store, session.ID, finding.ID, RunRequest{Confirm: true, PayloadID: "payload-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.PoCStatusInconclusive || result.PayloadID != "payload-1" || result.TargetID != finding.TargetID {
		t.Fatalf("unexpected result: %#v", result)
	}
	results, err := store.ListPoCResults(ctx, session.ID, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != result.ID || results[0].CompletedAt == nil {
		t.Fatalf("expected persisted completed result, got %#v", results)
	}
}

func pocTestStore(t *testing.T, title string) (*db.Store, models.Session, models.Finding) {
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
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityMedium, Title: title, Description: title, URL: "https://example.test", CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	return store, session, finding
}
