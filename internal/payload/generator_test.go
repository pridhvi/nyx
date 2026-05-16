package payload

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestGenerateReusesExistingPayloadsUnlessForced(t *testing.T) {
	ctx := context.Background()
	store, session, finding := payloadTestStore(t, "Reflected XSS")
	defer store.Close()

	first, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(second) != len(first) || second[0].ID != first[0].ID {
		t.Fatalf("expected reuse, first=%#v second=%#v", first, second)
	}
	forced, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(forced) != len(first) || forced[0].ID == first[0].ID {
		t.Fatalf("expected regenerated payload IDs, first=%#v forced=%#v", first, forced)
	}
}

func TestGenerateRejectsUnsupportedFinding(t *testing.T) {
	ctx := context.Background()
	store, session, finding := payloadTestStore(t, "Informational banner")
	defer store.Close()
	_, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err == nil || !strings.Contains(err.Error(), "not a supported") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func payloadTestStore(t *testing.T, title string) (*db.Store, models.Session, models.Finding) {
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
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityHigh, Title: title, Description: title, URL: "https://example.test/?q=x", Tags: []string{"test"}, CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	return store, session, finding
}
