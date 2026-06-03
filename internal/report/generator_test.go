package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
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
		Status:             models.FindingStatusOpen,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertFinding(ctx, models.Finding{
		ID:          models.NewID(),
		SessionID:   session.ID,
		TargetID:    target.ID,
		ToolID:      "html-escape-test",
		Type:        models.FindingTypeVulnerability,
		Severity:    models.SeverityMedium,
		Confidence:  0.6,
		Title:       `<script>alert("title")</script>`,
		Description: `<img src=x onerror=alert("description")>`,
		URL:         "https://example.com/unsafe",
		Status:      models.FindingStatusOpen,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	sourceFinding := models.SourceFinding{
		ID:                 models.NewID(),
		SessionID:          session.ID,
		Kind:               models.SourceKindSQLSink,
		Language:           "go",
		Framework:          "generic",
		FilePath:           "main.go",
		LineNumber:         12,
		Value:              "/search",
		ConfirmedByDynamic: true,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.InsertSourceFinding(ctx, sourceFinding); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertAttackGraphEdge(ctx, models.AttackGraphEdge{
		ID:         models.NewID(),
		SessionID:  session.ID,
		FromID:     "source:" + sourceFinding.ID,
		ToID:       "finding:" + finding.ID,
		Relation:   models.RelationConfirms,
		Confidence: 0.9,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertFinding(ctx, models.Finding{
		ID:         models.NewID(),
		SessionID:  session.ID,
		ToolID:     "audit/test",
		Type:       models.FindingTypeVulnerability,
		Severity:   models.SeverityLow,
		Confidence: 0.3,
		Title:      "Suppressed finding",
		URL:        "file://main.go#L20",
		Status:     models.FindingStatusSuppressed,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertCVEMatch(ctx, models.CVEMatch{
		ID:              models.NewID(),
		SessionID:       session.ID,
		CVEID:           "CVE-2024-1234",
		PackageName:     "demo",
		PackageVersion:  "1.0.0",
		Description:     "demo cve",
		Source:          "audit/grype",
		ConfidenceScore: 0.7,
	}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []models.ReportFormat{models.ReportFormatMarkdown, models.ReportFormatHTML, models.ReportFormatPDF, models.ReportFormatSARIF} {
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
		if format == models.ReportFormatMarkdown {
			body := string(artifact.Content)
			for _, expected := range []string{"Static Source Findings", "Cross-Confirmed Findings", "Tool Coverage", "Suppressed and Dismissed Findings", "package=demo@1.0.0"} {
				if !strings.Contains(body, expected) {
					t.Fatalf("expected markdown report to contain %q, got %s", expected, body)
				}
			}
		}
		if format == models.ReportFormatHTML {
			body := string(artifact.Content)
			if strings.Contains(body, "<script>") || strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;script&gt;") {
				t.Fatalf("expected HTML report to escape finding content, got %s", body)
			}
		}
		if format == models.ReportFormatSARIF {
			body := string(artifact.Content)
			if !strings.Contains(body, `"version": "2.1.0"`) || !strings.Contains(body, "High report finding") || strings.Contains(body, "Suppressed finding") {
				t.Fatalf("unexpected sarif body: %s", body)
			}
		}
	}
}
