package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	_ "modernc.org/sqlite"
)

func TestMigrationCreatesExpectedTables(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, table := range []string{
		"sessions",
		"targets",
		"findings",
		"http_evidence",
		"tool_runs",
		"technologies",
		"cve_matches",
		"attack_vectors",
		"llm_analyses",
		"plugins",
		"payloads",
		"credential_findings",
		"osint_findings",
		"ad_entities",
		"ad_relationships",
		"ad_artifacts",
		"block_events",
		"poc_results",
		"provider_statuses",
		"power_callbacks",
		"schema_migrations",
	} {
		var name string
		err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %s: %v", table, err)
		}
	}
	for _, version := range []string{"001_initial", "002_phase2_persistence", "003_operator_console", "004_tool_run_sidecars", "005_audit_source_mode", "006_power_features", "007_power_feature_depth", "008_plugin_integrity", "009_finding_status_enum"} {
		var got string
		if err := store.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, version).Scan(&got); err != nil {
			t.Fatalf("expected migration %s: %v", version, err)
		}
	}
}

func TestDefaultSessionsDirIsAbsoluteStatePath(t *testing.T) {
	dir := DefaultSessionsDir()
	if !filepath.IsAbs(dir) {
		t.Fatalf("expected absolute default sessions dir, got %q", dir)
	}
	if filepath.Base(dir) != "sessions" || filepath.Base(filepath.Dir(dir)) != ".nyx" {
		t.Fatalf("expected $HOME/.nyx/sessions style path, got %q", dir)
	}
}

func TestSessionDBPathStaysInsideSessionDir(t *testing.T) {
	dir := t.TempDir()
	sessionID := models.NewID()
	path, err := SessionDBPath(dir, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("expected absolute session DB path, got %q", path)
	}
	want := filepath.Join(dir, sessionID, "session.db")
	if path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}
	if !pathInsideOrEqual(dir, path) {
		t.Fatalf("expected %q to stay inside %q", path, dir)
	}
	for _, id := range []string{"../escape", "..", "nested/session", `nested\session`, ""} {
		if _, err := SessionDBPath(dir, id); err == nil {
			t.Fatalf("expected invalid session id %q to be rejected", id)
		}
	}
}

func TestCreateListShowDeleteSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	session := models.Session{
		ID:           models.NewID(),
		Name:         "Example",
		Status:       models.SessionStatusPending,
		Mode:         models.ScanModeActive,
		TargetInput:  "https://example.com",
		InScope:      []string{"https://example.com"},
		EnabledTools: []string{"http-probe", "ffuf"},
		ToolParameters: map[string]map[string]any{
			"ffuf": {"wordlist": "/tmp/words.txt"},
		},
		RunnerOptions: models.ScanRunnerOptions{Concurrency: 2, PerToolConcurrency: 1, ToolTimeoutSeconds: 30, ToolDelayMS: 50, RateLimit: "gentle"},
		CreatedAt:     time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.com", 443, "https")
	record, err := CreateSessionDB(ctx, dir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.DBPath); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(record.DBPath) != "session.db" || filepath.Base(filepath.Dir(record.DBPath)) != session.ID {
		t.Fatalf("expected directory session layout, got %q", record.DBPath)
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
	if len(got.EnabledTools) != 2 || got.EnabledTools[1] != "ffuf" {
		t.Fatalf("expected enabled tools to round-trip, got %#v", got.EnabledTools)
	}
	if got.ToolParameters["ffuf"]["wordlist"] != "/tmp/words.txt" {
		t.Fatalf("expected tool parameters to round-trip, got %#v", got.ToolParameters)
	}
	if got.RunnerOptions.Concurrency != 2 || got.RunnerOptions.RateLimit != "gentle" {
		t.Fatalf("expected runner options to round-trip, got %#v", got.RunnerOptions)
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
	if _, err := os.Stat(filepath.Dir(record.DBPath)); !os.IsNotExist(err) {
		t.Fatalf("expected deleted session directory, got err %v", err)
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
	legacy := models.NewID()
	if err := os.WriteFile(filepath.Join(dir, legacy+".db"), []byte("legacy"), 0o644); err != nil {
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
	if _, err := OpenSession(ctx, dir, legacy); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected legacy flat db to be ignored, got %v", err)
	}
}

func TestPhase2PersistenceRoundTrips(t *testing.T) {
	ctx := context.Background()
	session, target, store := createTestStore(t, ctx)

	technology := models.Technology{
		ID:         models.NewID(),
		TargetID:   target.ID,
		Name:       "nginx",
		Version:    "1.25.0",
		Category:   "server",
		Confidence: 0.86,
		SourceTool: "whatweb",
	}
	if err := store.InsertTechnology(ctx, technology); err != nil {
		t.Fatal(err)
	}

	finding := models.Finding{
		ID:                 models.NewID(),
		SessionID:          session.ID,
		TargetID:           target.ID,
		ToolID:             "sqlmap",
		Type:               models.FindingTypeVulnerability,
		Severity:           models.SeverityHigh,
		Confidence:         0.9,
		CVSSScore:          8.1,
		Title:              "SQL injection",
		Description:        "Injected parameter accepted a boolean payload.",
		Remediation:        "Use parameterized queries.",
		URL:                "https://example.com/search?q=1",
		Parameter:          "q",
		Method:             "GET",
		EvidenceRaw:        "sqlmap evidence",
		EvidenceNormalized: `{"parameter":"q"}`,
		Tags:               []string{"owasp:A03", "cwe:89"},
		HTTPEvidence: &models.HTTPEvidence{
			RequestRaw:   "GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			ResponseRaw:  "HTTP/1.1 200 OK\r\n\r\nok",
			StatusCode:   200,
			ResponseTime: 123,
		},
		CVEMatches: []models.CVEMatch{{
			ID:               models.NewID(),
			CVEID:            "CVE-2024-0001",
			CVSSv3Score:      7.5,
			CVSSv3Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description:      "Example CVE",
			AffectedVersion:  "1.25.0",
			FixedVersion:     "1.25.1",
			PatchAvailable:   true,
			ExploitAvailable: false,
			References:       []string{"https://example.com/cve"},
			Source:           "nvd",
			ConfidenceScore:  0.77,
		}},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}

	techCVE := models.CVEMatch{
		ID:               models.NewID(),
		TechnologyID:     technology.ID,
		CVEID:            "CVE-2024-0002",
		CVSSv3Score:      9.8,
		Description:      "Technology CVE",
		AffectedVersion:  "1.25.0",
		FixedVersion:     "1.25.2",
		PatchAvailable:   true,
		ExploitAvailable: true,
		References:       []string{"https://example.com/tech-cve"},
		Source:           "nvd",
		ConfidenceScore:  0.88,
	}
	if err := store.InsertCVEMatch(ctx, techCVE); err != nil {
		t.Fatal(err)
	}

	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].Technologies) != 1 || targets[0].Technologies[0].Name != "nginx" {
		t.Fatalf("unexpected targets with technologies: %#v", targets)
	}

	findings, err := store.ListFindings(ctx, session.ID, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].HTTPEvidence == nil || findings[0].HTTPEvidence.StatusCode != 200 {
		t.Fatalf("expected finding with HTTP evidence, got %#v", findings)
	}
	if len(findings[0].CVEMatches) != 1 || findings[0].CVEMatches[0].FixedVersion != "1.25.1" {
		t.Fatalf("expected finding CVE match, got %#v", findings[0].CVEMatches)
	}

	sessionCVEs, err := store.ListCVEMatchesBySession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessionCVEs) != 2 {
		t.Fatalf("expected 2 session CVEs, got %#v", sessionCVEs)
	}
}

func TestAttackVectorLLMAndPluginPersistenceRoundTrips(t *testing.T) {
	ctx := context.Background()
	session, _, store := createTestStore(t, ctx)

	vector := models.AttackVector{
		ID:               models.NewID(),
		SessionID:        session.ID,
		Title:            "Exploit injection",
		Description:      "SQL injection can expose data.",
		Narrative:        "An attacker abuses the injectable parameter.",
		OWASPCategory:    "A03:2021 - Injection",
		Severity:         models.SeverityCritical,
		Confidence:       0.82,
		PrereqFindingIDs: []string{"finding-1"},
		LLMReviewed:      true,
		LLMNotes:         "Narrative only.",
		CreatedAt:        time.Now().UTC(),
		Steps: []models.AttackStep{{
			Order:         1,
			Description:   "Exploit injectable search parameter.",
			FindingID:     "finding-1",
			ToolSuggested: "sqlmap --level 5",
		}},
	}
	if err := store.InsertAttackVector(ctx, vector); err != nil {
		t.Fatal(err)
	}
	vectors, err := store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 || len(vectors[0].Steps) != 1 || vectors[0].Steps[0].ToolSuggested == "" {
		t.Fatalf("unexpected vectors: %#v", vectors)
	}

	analysis := models.LLMAnalysis{
		ID:            models.NewID(),
		SessionID:     session.ID,
		ModelID:       "llama3:8b",
		PromptSummary: "Summarize injection risk.",
		Messages: []models.LLMMessage{{
			Role:    "assistant",
			Content: "Use parameterized queries.",
			ToolCalls: []models.LLMToolCall{{
				ID:        "call-1",
				Name:      "lookup_cve",
				Arguments: `{"technology":"nginx"}`,
				Result:    "[]",
			}},
		}},
		TotalTokens: 42,
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertLLMAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	analyses, err := store.ListLLMAnalyses(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 || analyses[0].Messages[0].ToolCalls[0].Name != "lookup_cve" {
		t.Fatalf("unexpected analyses: %#v", analyses)
	}

	plugin := models.PluginRecord{
		ID:        models.NewID(),
		Name:      "custom-scanner",
		Binary:    "/opt/nyx/custom-scanner",
		SHA256:    "old-digest",
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.UpsertPlugin(ctx, plugin); err != nil {
		t.Fatal(err)
	}
	plugin.Binary = "/opt/nyx/custom-scanner-v2"
	plugin.SHA256 = "new-digest"
	plugin.UpdatedAt = plugin.UpdatedAt.Add(time.Minute)
	if err := store.UpsertPlugin(ctx, plugin); err != nil {
		t.Fatal(err)
	}
	plugins, err := store.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 1 || plugins[0].Binary != "/opt/nyx/custom-scanner-v2" || plugins[0].SHA256 != "new-digest" {
		t.Fatalf("unexpected plugins: %#v", plugins)
	}
	if err := store.DeletePlugin(ctx, plugin.Name); err != nil {
		t.Fatal(err)
	}
	plugins, err = store.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected plugin delete, got %#v", plugins)
	}
}

func TestExistingInitialDatabaseMigratesToPhase2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	body, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	oldInitial := strings.ReplaceAll(string(body), "stdout_path", "stdout_raw")
	oldInitial = strings.ReplaceAll(oldInitial, "stderr_path", "stderr_raw")
	if _, err := database.ExecContext(ctx, oldInitial); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ('001_initial', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, column := range []string{"affected_version", "fixed_version"} {
		var name string
		if err := store.db.QueryRowContext(ctx, `SELECT name FROM pragma_table_info('cve_matches') WHERE name = ?`, column).Scan(&name); err != nil {
			t.Fatalf("expected cve_matches.%s after migration: %v", column, err)
		}
	}
	var pluginTable string
	if err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'plugins'`).Scan(&pluginTable); err != nil {
		t.Fatalf("expected plugins table after migration: %v", err)
	}
	for _, expected := range []string{"002_phase2_persistence", "003_operator_console", "004_tool_run_sidecars", "005_audit_source_mode", "006_power_features", "007_power_feature_depth", "008_plugin_integrity", "009_finding_status_enum"} {
		var version string
		if err := store.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, expected).Scan(&version); err != nil {
			t.Fatalf("expected %s migration record: %v", expected, err)
		}
	}
	for _, column := range []string{"stdout_path", "stderr_path"} {
		var name string
		if err := store.db.QueryRowContext(ctx, `SELECT name FROM pragma_table_info('tool_runs') WHERE name = ?`, column).Scan(&name); err != nil {
			t.Fatalf("expected tool_runs.%s after migration: %v", column, err)
		}
	}
	for _, column := range []string{"stdout_raw", "stderr_raw"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('tool_runs') WHERE name = ?`, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expected tool_runs.%s to be removed", column)
		}
	}
	for _, column := range []string{"workload_mode", "source_path"} {
		var name string
		if err := store.db.QueryRowContext(ctx, `SELECT name FROM pragma_table_info('sessions') WHERE name = ?`, column).Scan(&name); err != nil {
			t.Fatalf("expected sessions.%s after migration: %v", column, err)
		}
	}
	for _, table := range []string{"source_findings", "attack_graph_edges"} {
		var name string
		if err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name); err != nil {
			t.Fatalf("expected %s table after migration: %v", table, err)
		}
	}
}

func TestAuditSourcePersistenceAndStats(t *testing.T) {
	ctx := context.Background()
	session, target, store := createTestStore(t, ctx)

	staticFinding := models.Finding{
		ID:          models.NewID(),
		SessionID:   session.ID,
		ToolID:      "audit/semgrep",
		Type:        models.FindingTypeVulnerability,
		Severity:    models.SeverityHigh,
		Confidence:  0.7,
		Title:       "Static SQL sink",
		URL:         "file://app.py#L10",
		CodeContext: "db.execute(query)",
		Status:      models.FindingStatusConfirmed,
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, staticFinding); err != nil {
		t.Fatal(err)
	}
	dynamicFinding := models.Finding{
		ID:         models.NewID(),
		SessionID:  session.ID,
		TargetID:   target.ID,
		ToolID:     "sqlmap",
		Type:       models.FindingTypeVulnerability,
		Severity:   models.SeverityHigh,
		Confidence: 0.8,
		Title:      "Dynamic SQL injection",
		URL:        "https://example.com/search?q=1",
		CreatedAt:  time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, dynamicFinding); err != nil {
		t.Fatal(err)
	}
	sourceFinding := models.SourceFinding{
		ID:         models.NewID(),
		SessionID:  session.ID,
		Kind:       models.SourceKindSQLSink,
		Language:   "python",
		Framework:  "generic",
		FilePath:   "app.py",
		LineNumber: 10,
		Value:      "/search",
		Context:    "db.execute(query)",
		CreatedAt:  time.Now().UTC(),
	}
	if err := store.InsertSourceFinding(ctx, sourceFinding); err != nil {
		t.Fatal(err)
	}
	edge := models.AttackGraphEdge{
		ID:         models.NewID(),
		SessionID:  session.ID,
		FromID:     "source:" + sourceFinding.ID,
		ToID:       "finding:" + dynamicFinding.ID,
		Relation:   models.RelationConfirms,
		Confidence: 0.9,
		CreatedAt:  time.Now().UTC(),
	}
	if err := store.InsertAttackGraphEdge(ctx, edge); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSourceFindingConfirmed(ctx, sourceFinding.ID); err != nil {
		t.Fatal(err)
	}
	cve := models.CVEMatch{
		ID:              models.NewID(),
		SessionID:       session.ID,
		CVEID:           "CVE-2024-9999",
		PackageName:     "demo",
		PackageVersion:  "1.0.0",
		Description:     "demo package CVE",
		Source:          "audit/grype",
		ConfidenceScore: 0.7,
	}
	if err := store.InsertCVEMatch(ctx, cve); err != nil {
		t.Fatal(err)
	}

	stats, err := store.Stats(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.StaticFindingCount != 1 || stats.DynamicFindingCount != 1 || stats.SourceFindingCount != 1 || stats.ConfirmedByBoth != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	sourceFindings, err := store.ListSourceFindings(ctx, session.ID, SourceFindingFilter{Kind: string(models.SourceKindSQLSink)})
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceFindings) != 1 || !sourceFindings[0].ConfirmedByDynamic {
		t.Fatalf("unexpected source findings: %#v", sourceFindings)
	}
	edges, err := store.ListAttackGraphEdges(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].Relation != models.RelationConfirms {
		t.Fatalf("unexpected graph edges: %#v", edges)
	}
	cves, err := store.ListCVEMatchesBySession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 1 || cves[0].PackageName != "demo" || cves[0].PackageVersion != "1.0.0" {
		t.Fatalf("unexpected cves: %#v", cves)
	}
}

func TestPowerDepthStoreProviderStatusesAndCallbacks(t *testing.T) {
	ctx := context.Background()
	session, target, store := createTestStore(t, ctx)
	status := models.ProviderStatus{
		ID:        models.NewID(),
		SessionID: session.ID,
		Provider:  "github",
		Module:    "code_search",
		Status:    "skipped",
		Message:   "missing token",
		Metadata:  map[string]any{"required": true},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.InsertProviderStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.ListProviderStatuses(ctx, session.ID, ProviderStatusFilter{Provider: "github"})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Status != "skipped" || statuses[0].Metadata["required"] != true {
		t.Fatalf("unexpected provider statuses: %#v", statuses)
	}

	finding := models.Finding{
		ID:        models.NewID(),
		SessionID: session.ID,
		TargetID:  target.ID,
		ToolID:    "fixture",
		Type:      models.FindingTypeVulnerability,
		Severity:  models.SeverityMedium,
		Title:     "Callback target",
		URL:       "https://example.com/callback",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	callback := models.PowerCallback{
		ID:        models.NewID(),
		SessionID: session.ID,
		FindingID: finding.ID,
		Provider:  "builtin",
		Token:     "token-1",
		URL:       "http://127.0.0.1/callback/token-1",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.InsertPowerCallback(ctx, callback); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPowerCallbackReceived(ctx, session.ID, callback.Token, "127.0.0.1", "GET /callback/token-1"); err != nil {
		t.Fatal(err)
	}
	callbacks, err := store.ListPowerCallbacks(ctx, session.ID, PowerCallbackFilter{FindingID: finding.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(callbacks) != 1 || !callbacks[0].Received || callbacks[0].SourceIP != "127.0.0.1" || callbacks[0].UpdatedAt.IsZero() {
		t.Fatalf("unexpected callbacks: %#v", callbacks)
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

func createTestStore(t *testing.T, ctx context.Context) (models.Session, models.Target, *Store) {
	t.Helper()
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
	sessionDir := t.TempDir()
	_, err := CreateSessionDB(ctx, sessionDir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSession(ctx, sessionDir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	return session, target, store
}
