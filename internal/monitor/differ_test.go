package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func TestDifferDetectsNewAndResolvedFindings(t *testing.T) {
	ctx := context.Background()
	sessionDir := t.TempDir()
	baseID := "base0000000000000000000000000000"
	currentID := "curr0000000000000000000000000000"
	baseTarget := target(baseID, "base-target", "example.test", 443, "https")
	currentTarget := target(currentID, "current-target", "example.test", 443, "https")
	if err := createSession(ctx, sessionDir, baseID, baseTarget, []models.Finding{finding(baseID, baseTarget.ID, "missing-csp", models.SeverityMedium)}); err != nil {
		t.Fatal(err)
	}
	if err := createSession(ctx, sessionDir, currentID, currentTarget, []models.Finding{finding(currentID, currentTarget.ID, "exposed-admin", models.SeverityHigh)}); err != nil {
		t.Fatal(err)
	}
	changes, err := Differ{SessionDir: sessionDir}.DiffSessions(ctx, baseID, currentID, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	var newFinding, resolvedFinding bool
	for _, change := range changes {
		if change.ChangeType == models.SurfaceChangeNewFinding && change.Severity == models.SeverityHigh {
			newFinding = true
		}
		if change.ChangeType == models.SurfaceChangeResolvedFinding {
			resolvedFinding = true
		}
	}
	if !newFinding || !resolvedFinding {
		t.Fatalf("expected new and resolved finding changes, got %#v", changes)
	}
}

func TestDifferDetectsFindingSeverityChanges(t *testing.T) {
	ctx := context.Background()
	sessionDir := t.TempDir()
	baseID := "base2000000000000000000000000000"
	currentID := "curr2000000000000000000000000000"
	baseTarget := target(baseID, "base-target", "example.test", 443, "https")
	currentTarget := target(currentID, "current-target", "example.test", 443, "https")
	if err := createSession(ctx, sessionDir, baseID, baseTarget, []models.Finding{finding(baseID, baseTarget.ID, "missing-csp", models.SeverityLow)}); err != nil {
		t.Fatal(err)
	}
	if err := createSession(ctx, sessionDir, currentID, currentTarget, []models.Finding{finding(currentID, currentTarget.ID, "missing-csp", models.SeverityHigh)}); err != nil {
		t.Fatal(err)
	}
	changes, err := Differ{SessionDir: sessionDir}.DiffSessions(ctx, baseID, currentID, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range changes {
		if change.ChangeType == models.SurfaceChangeSeverityChanged {
			if change.PreviousValue != string(models.SeverityLow) || change.CurrentValue != string(models.SeverityHigh) || change.Severity != models.SeverityHigh {
				t.Fatalf("unexpected severity change: %#v", change)
			}
			return
		}
	}
	t.Fatalf("expected severity change, got %#v", changes)
}

func TestDifferDetectsNewHostAndTechnology(t *testing.T) {
	ctx := context.Background()
	sessionDir := t.TempDir()
	baseID := "base1000000000000000000000000000"
	currentID := "curr1000000000000000000000000000"
	baseTarget := target(baseID, "base-target", "example.test", 443, "https")
	currentTarget := target(currentID, "current-target", "example.test", 443, "https")
	newTarget := target(currentID, "new-target", "api.example.test", 8443, "https")
	newTarget.Technologies = []models.Technology{{ID: "tech-1", TargetID: newTarget.ID, Name: "nginx", Version: "1.25", Category: "server", Confidence: 0.9, SourceTool: "test"}}
	if err := createSession(ctx, sessionDir, baseID, baseTarget, nil); err != nil {
		t.Fatal(err)
	}
	if err := createSessionWithTargets(ctx, sessionDir, currentID, []models.Target{currentTarget, newTarget}, nil); err != nil {
		t.Fatal(err)
	}
	changes, err := Differ{SessionDir: sessionDir}.DiffSessions(ctx, baseID, currentID, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	var newHost, newTech bool
	for _, change := range changes {
		if change.ChangeType == models.SurfaceChangeNewHost {
			newHost = true
		}
		if change.ChangeType == models.SurfaceChangeNewTechnology {
			newTech = true
		}
	}
	if !newHost || !newTech {
		t.Fatalf("expected new host and technology changes, got %#v", changes)
	}
}

func createSession(ctx context.Context, dir, sessionID string, target models.Target, findings []models.Finding) error {
	return createSessionWithTargets(ctx, dir, sessionID, []models.Target{target}, findings)
}

func createSessionWithTargets(ctx context.Context, dir, sessionID string, targets []models.Target, findings []models.Finding) error {
	session := models.Session{
		ID:           sessionID,
		Name:         sessionID,
		Status:       models.SessionStatusCompleted,
		Mode:         models.ScanModeActive,
		WorkloadMode: models.WorkloadModeDynamic,
		TargetInput:  "https://example.test",
		InScope:      []string{"example.test", "api.example.test"},
		CreatedAt:    time.Now().UTC(),
	}
	if _, err := db.CreateSessionDBWithTargets(ctx, dir, session, targets); err != nil {
		return err
	}
	store, err := db.OpenSession(ctx, dir, sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	for _, finding := range findings {
		if err := store.InsertFinding(ctx, finding); err != nil {
			return err
		}
	}
	return store.UpdateSessionCounts(ctx, sessionID)
}

func target(sessionID, id, host string, port int, protocol string) models.Target {
	return models.Target{
		ID:           id,
		SessionID:    sessionID,
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		IsAlive:      true,
		DiscoveredBy: "test",
		CreatedAt:    time.Now().UTC(),
	}
}

func finding(sessionID, targetID, title string, severity models.Severity) models.Finding {
	return models.Finding{
		ID:          models.NewID(),
		SessionID:   sessionID,
		TargetID:    targetID,
		ToolID:      "test",
		Type:        models.FindingTypeMisconfiguration,
		Severity:    severity,
		Confidence:  0.9,
		Title:       title,
		Description: title,
		URL:         "https://example.test/" + title,
		Tags:        []string{"test"},
		CreatedAt:   time.Now().UTC(),
	}
}
