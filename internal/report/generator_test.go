package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

func TestGenerateMarkdownHTMLAndPDFReports(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Report Test",
		Status:      models.SessionStatusCompleted,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"https://example.com"},
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "example.com", Port: 443, Protocol: "https", IsAlive: true, DiscoveredBy: "test", CreatedAt: time.Now().UTC()}
	if err := store.InsertTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{
		ID:                 models.NewID(),
		SessionID:          session.ID,
		TargetID:           target.ID,
		ToolID:             "test",
		Type:               models.FindingTypeVulnerability,
		Severity:           models.SeverityHigh,
		Confidence:         0.9,
		CVSSScore:          8.2,
		Title:              "High report finding",
		Description:        "A high finding.",
		Remediation:        "Patch it.",
		URL:                "https://example.com",
		EvidenceRaw:        "raw evidence",
		EvidenceNormalized: "normalized evidence",
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	for _, format := range []models.ReportFormat{models.ReportFormatMarkdown, models.ReportFormatHTML, models.ReportFormatPDF} {
		artifact, err := Generate(ctx, store, Options{Format: format, Mode: models.ReportModeTechnical})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifact.Content) == 0 || artifact.Report.SessionID != session.ID {
			t.Fatalf("empty report for format %s: %#v", format, artifact)
		}
		if format == models.ReportFormatPDF && !strings.HasPrefix(string(artifact.Content), "%PDF-") {
			t.Fatalf("expected PDF header, got %q", string(artifact.Content[:4]))
		}
	}
}
