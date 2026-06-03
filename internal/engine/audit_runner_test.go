package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func TestAuditRunnerSuppressionDiffAndSidecarLogs(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("@app.get(\"/admin\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".nyx-audit-ignore"), []byte("fixture:suppress:app.py\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	session, store := testAuditStore(t, ctx, repo)
	runner := &AuditRunner{
		store: store,
		adapters: []adapters.StaticAdapter{
			fakeStaticAdapter{id: "fixture", findings: []models.Finding{
				auditFinding(session.ID, "audit/fixture", "file://app.py#L1", []string{"audit", "fixture", "suppress"}),
				auditFinding(session.ID, "audit/fixture", "file://other.py#L1", []string{"audit", "fixture", "keep"}),
			}, stdout: "stdout", stderr: "stderr"},
		},
		options: AuditOptions{DiffPaths: []string{"app.py"}, NoLLM: true},
	}
	if err := runner.Run(ctx, session, repo); err != nil {
		t.Fatal(err)
	}
	findings, err := store.ListFindings(ctx, session.ID, db.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Status != "suppressed" {
		t.Fatalf("expected only suppressed diff-matching finding, got %#v", findings)
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].StdoutPath == "" || runs[0].StderrPath == "" {
		t.Fatalf("expected sidecar log paths, got %#v", runs)
	}
}

func TestAuditRunnerMissingOptionalAndRequiredTools(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("@app.get(\"/\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	session, store := testAuditStore(t, ctx, repo)
	optional := &AuditRunner{store: store, adapters: []adapters.StaticAdapter{fakeStaticAdapter{id: "missing", available: false}}, options: AuditOptions{NoLLM: true}}
	if err := optional.Run(ctx, session, repo); err != nil {
		t.Fatalf("expected missing optional tool to be non-fatal, got %v", err)
	}
	required := &AuditRunner{store: store, adapters: []adapters.StaticAdapter{fakeStaticAdapter{id: "missing", available: false}}, options: AuditOptions{Tools: []string{"audit/missing"}, NoLLM: true}}
	if err := required.Run(ctx, session, repo); err == nil {
		t.Fatal("expected explicit missing audit tool to fail")
	}
}

func TestCombinedModeSourceHintsAndGraphConfirmation(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("@app.get(\"/search\")\ndef search():\n    q = request.args.get(\"q\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	session, store := testCombinedStore(t, ctx, repo)
	audit := &AuditRunner{
		store:    store,
		adapters: []adapters.StaticAdapter{fakeStaticAdapter{id: "noop"}},
		options:  AuditOptions{NoLLM: true, KeepSessionOpen: true},
	}
	if err := audit.Run(ctx, session, repo); err != nil {
		t.Fatal(err)
	}
	var sawSourceHints bool
	dynamic := fakeRunnerAdapter{
		id: "dynamic",
		runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
			sawSourceHints = len(input.SourceFindings) > 0
			return adapters.AdapterOutput{
				Findings: []models.Finding{{
					ID:         models.NewID(),
					SessionID:  input.Session.ID,
					TargetID:   input.Target.ID,
					ToolID:     "dynamic",
					Type:       models.FindingTypeVulnerability,
					Severity:   models.SeverityHigh,
					Confidence: 0.9,
					Title:      "Dynamic /search finding",
					URL:        "https://example.com/search?q=1",
					Parameter:  "q",
					CreatedAt:  time.Now().UTC(),
				}},
				ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "dynamic", StartedAt: time.Now().UTC()},
			}, nil
		},
	}
	runner := NewRunnerWithOptions(store, []adapters.Adapter{dynamic}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if !sawSourceHints {
		t.Fatal("expected dynamic adapter to receive persisted source hints")
	}
	sourceFindings, err := store.ListSourceFindings(ctx, session.ID, db.SourceFindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	confirmed := false
	for _, finding := range sourceFindings {
		confirmed = confirmed || finding.ConfirmedByDynamic
	}
	if !confirmed {
		t.Fatalf("expected source finding to be confirmed by graph edge, got %#v", sourceFindings)
	}
	edges, err := store.ListAttackGraphEdges(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range edges {
		if edge.Relation == models.RelationConfirms {
			return
		}
	}
	t.Fatalf("expected confirm edge, got %#v", edges)
}

type fakeStaticAdapter struct {
	id        string
	available bool
	findings  []models.Finding
	cves      []models.CVEMatch
	stdout    string
	stderr    string
	err       error
}

func (a fakeStaticAdapter) ID() string          { return a.id }
func (a fakeStaticAdapter) Name() string        { return a.id }
func (a fakeStaticAdapter) Languages() []string { return []string{"any"} }
func (a fakeStaticAdapter) Available() bool {
	if a.available {
		return true
	}
	return a.err == nil && a.id != "missing"
}
func (a fakeStaticAdapter) Run(ctx context.Context, input adapters.StaticAdapterInput) (adapters.StaticAdapterOutput, error) {
	if a.err != nil {
		return adapters.StaticAdapterOutput{}, a.err
	}
	run := models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.SessionID,
		ToolID:    a.id,
		RawStdout: a.stdout,
		RawStderr: a.stderr,
		StartedAt: time.Now().UTC(),
	}
	return adapters.StaticAdapterOutput{Findings: a.findings, CVEs: a.cves, ToolRun: run}, nil
}

func auditFinding(sessionID, toolID, url string, tags []string) models.Finding {
	return models.Finding{
		ID:         models.NewID(),
		SessionID:  sessionID,
		ToolID:     toolID,
		Type:       models.FindingTypeVulnerability,
		Severity:   models.SeverityMedium,
		Confidence: 0.5,
		Title:      "audit finding",
		URL:        url,
		Tags:       tags,
		Status:     models.FindingStatusOpen,
		CreatedAt:  time.Now().UTC(),
	}
}

func testAuditStore(t *testing.T, ctx context.Context, repo string) (models.Session, *db.Store) {
	t.Helper()
	session := models.Session{
		ID:           models.NewID(),
		Status:       models.SessionStatusPending,
		Mode:         models.ScanModePassive,
		WorkloadMode: models.WorkloadModeStatic,
		SourcePath:   repo,
		CreatedAt:    time.Now().UTC(),
	}
	dir := t.TempDir()
	if _, err := db.CreateSessionDBWithTargets(ctx, dir, session, nil); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return session, store
}

func testCombinedStore(t *testing.T, ctx context.Context, repo string) (models.Session, *db.Store) {
	t.Helper()
	session := models.Session{
		ID:           models.NewID(),
		Status:       models.SessionStatusPending,
		Mode:         models.ScanModeActive,
		WorkloadMode: models.WorkloadModeCombined,
		TargetInput:  "https://example.com",
		InScope:      []string{"https://example.com"},
		SourcePath:   repo,
		CreatedAt:    time.Now().UTC(),
	}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "example.com", Port: 443, Protocol: "https", IsAlive: true, DiscoveredBy: "test", CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return session, store
}
