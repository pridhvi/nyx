package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	appconfig "github.com/pridhvi/nyx/internal/config"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/state"
)

func TestSPASecurityHeaders(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()

	for _, path := range []string{"/", "/sessions/example/findings"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", got)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("X-Frame-Options = %q", got)
			}
			csp := rec.Header().Get("Content-Security-Policy")
			for _, want := range []string{
				"default-src 'self'",
				"script-src 'self'",
				"style-src 'self'",
				"connect-src 'self'",
				"object-src 'none'",
				"frame-ancestors 'none'",
				"base-uri 'self'",
			} {
				if !strings.Contains(csp, want) {
					t.Fatalf("Content-Security-Policy %q does not contain %q", csp, want)
				}
			}
			if strings.Contains(csp, " ws:") || strings.Contains(csp, " wss:") {
				t.Fatalf("Content-Security-Policy allows broad websocket destinations: %q", csp)
			}
			if strings.Contains(csp, "'unsafe-inline'") {
				t.Fatalf("Content-Security-Policy allows inline styles or scripts: %q", csp)
			}
		})
	}
}

func TestAPISecurityHeadersDoNotSetSPACSP(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Fatalf("API Content-Security-Policy = %q", got)
	}
}

func TestHealthDoesNotExposeSessionDirectory(t *testing.T) {
	sessionDir := t.TempDir()
	handler := NewServer(Config{SessionDir: sessionDir}).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), sessionDir) {
		t.Fatalf("health response exposed session dir %q: %s", sessionDir, rec.Body.String())
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["sessions_dir"]; ok {
		t.Fatalf("health response includes sessions_dir: %#v", payload)
	}
	if payload["db_dir_ready"] != true {
		t.Fatalf("expected db_dir_ready true, got %#v", payload["db_dir_ready"])
	}
	if payload["session_dir_status"] != "ready" {
		t.Fatalf("expected session_dir_status ready, got %#v", payload["session_dir_status"])
	}
}

func TestEffectiveConfigDoesNotExposeLocalPaths(t *testing.T) {
	sessionDir := t.TempDir()
	toolDir := t.TempDir()
	pluginDir := t.TempDir()
	cfg := appconfig.Default()
	cfg.Database.SessionDir = sessionDir
	cfg.CVE.OfflinePath = filepath.Join(sessionDir, "nvd.json")
	cfg.CVE.ExploitDBPath = filepath.Join(sessionDir, "exploitdb")
	cfg.Tools = map[string]string{"ffuf": filepath.Join(toolDir, "ffuf")}
	cfg.Plugins = []string{filepath.Join(pluginDir, "plugin")}
	handler := NewServer(Config{SessionDir: sessionDir, AppConfig: cfg, ToolPaths: cfg.Tools}).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config/effective", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leaked := range []string{sessionDir, toolDir, pluginDir, cfg.CVE.OfflinePath, cfg.CVE.ExploitDBPath, cfg.Plugins[0]} {
		if strings.Contains(body, leaked) {
			t.Fatalf("effective config leaked local path %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, `"session_dir_status":"ready"`) || !strings.Contains(body, `"ffuf":"configured"`) || !strings.Contains(body, `"plugins":["configured"]`) {
		t.Fatalf("expected readiness/configured indicators, got %s", body)
	}
}

func TestSessionAPI(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Nyx Test</title>"))
	}))
	defer targetServer.Close()

	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client(), LLMAllowedHosts: []string{"127.0.0.1"}})
	handler := server.Handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nhealth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Example","mode":"active","out_of_scope":["admin.example.com"],"tools":["http-probe","security-headers","ffuf"],"tool_parameters":{"ffuf":{"wordlist":"` + wordlist + `","timeout_seconds":5}}}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, jsonRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Session.ID == "" || created.Session.TargetInput != targetServer.URL || created.Session.Status != "pending" {
		t.Fatalf("unexpected created session: %#v", created.Session)
	}
	waitForCompletedScan(t, handler, created.Session.ID)

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	var sessions []db.SessionRecord
	if err := json.NewDecoder(list.Body).Decode(&sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Session.ID != created.Session.ID {
		t.Fatalf("unexpected sessions: %#v", sessions)
	}

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get status = %d", get.Code)
	}

	targets := httptest.NewRecorder()
	handler.ServeHTTP(targets, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/targets", nil))
	if targets.Code != http.StatusOK {
		t.Fatalf("targets status = %d", targets.Code)
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/scan/"+created.Session.ID+"/status", nil))
	if status.Code != http.StatusOK {
		t.Fatalf("scan status = %d", status.Code)
	}
	var decodedStatus struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		CurrentPhase string `json:"current_phase"`
		Phases       []struct {
			Phase          string `json:"phase"`
			Status         string `json:"status"`
			CompletedTools int    `json:"completed_tools"`
			FindingCount   int    `json:"finding_count"`
		} `json:"phases"`
		Tools []struct {
			ToolID       string `json:"tool_id"`
			Phase        string `json:"phase"`
			Status       string `json:"status"`
			FindingCount int    `json:"finding_count"`
		} `json:"tools"`
	}
	if err := json.NewDecoder(status.Body).Decode(&decodedStatus); err != nil {
		t.Fatal(err)
	}
	if decodedStatus.ID != created.Session.ID || decodedStatus.Status == "" {
		t.Fatalf("unexpected scan status response: %#v", decodedStatus)
	}
	if len(decodedStatus.Phases) == 0 || len(decodedStatus.Tools) == 0 {
		t.Fatalf("expected phase and tool progress in scan status: %#v", decodedStatus)
	}
	statusTools := map[string]string{}
	for _, tool := range decodedStatus.Tools {
		statusTools[tool.ToolID] = tool.Status
	}
	for _, toolID := range []string{"http-probe", "security-headers", "ffuf"} {
		if statusTools[toolID] == "" {
			t.Fatalf("expected scan status tool progress for %s in %#v", toolID, statusTools)
		}
	}

	findings := httptest.NewRecorder()
	handler.ServeHTTP(findings, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/findings", nil))
	if findings.Code != http.StatusOK {
		t.Fatalf("findings status = %d", findings.Code)
	}
	var decodedFindings []models.Finding
	if err := json.NewDecoder(findings.Body).Decode(&decodedFindings); err != nil {
		t.Fatal(err)
	}
	if len(decodedFindings) == 0 {
		t.Fatal("expected security header findings")
	}
	emptyFindingUpdate := httptest.NewRecorder()
	handler.ServeHTTP(emptyFindingUpdate, jsonRequest(http.MethodPatch, "/api/sessions/"+created.Session.ID+"/findings/"+decodedFindings[0].ID, bytes.NewBufferString(`{}`)))
	if emptyFindingUpdate.Code != http.StatusBadRequest || !strings.Contains(emptyFindingUpdate.Body.String(), "no fields to update") {
		t.Fatalf("expected empty finding update rejection, got %d body=%s", emptyFindingUpdate.Code, emptyFindingUpdate.Body.String())
	}
	invalidFindingStatus := httptest.NewRecorder()
	handler.ServeHTTP(invalidFindingStatus, jsonRequest(http.MethodPatch, "/api/sessions/"+created.Session.ID+"/findings/"+decodedFindings[0].ID, bytes.NewBufferString(`{"status":"needs-review"}`)))
	if invalidFindingStatus.Code != http.StatusBadRequest || !strings.Contains(invalidFindingStatus.Body.String(), "invalid finding status") {
		t.Fatalf("expected invalid finding status rejection, got %d body=%s", invalidFindingStatus.Code, invalidFindingStatus.Body.String())
	}
	validFindingStatus := httptest.NewRecorder()
	handler.ServeHTTP(validFindingStatus, jsonRequest(http.MethodPatch, "/api/sessions/"+created.Session.ID+"/findings/"+decodedFindings[0].ID, bytes.NewBufferString(`{"status":"false-positive"}`)))
	if validFindingStatus.Code != http.StatusOK {
		t.Fatalf("valid finding status update = %d body=%s", validFindingStatus.Code, validFindingStatus.Body.String())
	}
	var updatedFinding models.Finding
	if err := json.NewDecoder(validFindingStatus.Body).Decode(&updatedFinding); err != nil {
		t.Fatal(err)
	}
	if updatedFinding.Status != models.FindingStatusFalsePositive {
		t.Fatalf("expected false-positive finding status, got %#v", updatedFinding.Status)
	}
	invalidFindingFilter := httptest.NewRecorder()
	handler.ServeHTTP(invalidFindingFilter, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/findings?status=needs-review", nil))
	if invalidFindingFilter.Code != http.StatusBadRequest || !strings.Contains(invalidFindingFilter.Body.String(), "invalid finding status") {
		t.Fatalf("expected invalid finding status filter rejection, got %d body=%s", invalidFindingFilter.Code, invalidFindingFilter.Body.String())
	}

	runs := httptest.NewRecorder()
	handler.ServeHTTP(runs, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/tool-runs", nil))
	if runs.Code != http.StatusOK {
		t.Fatalf("tool runs status = %d", runs.Code)
	}
	var decodedRuns []models.ToolRun
	if err := json.NewDecoder(runs.Body).Decode(&decodedRuns); err != nil {
		t.Fatal(err)
	}
	runIDs := map[string]bool{}
	for _, run := range decodedRuns {
		runIDs[run.ToolID] = true
	}
	for _, toolID := range []string{"http-probe", "security-headers", "ffuf"} {
		if !runIDs[toolID] {
			t.Fatalf("expected tool run %s in %#v", toolID, runIDs)
		}
	}
	var runWithLog models.ToolRun
	for _, run := range decodedRuns {
		if run.StdoutPath != "" {
			runWithLog = run
			break
		}
	}
	if runWithLog.ID == "" {
		t.Fatalf("expected at least one tool run stdout sidecar, got %#v", decodedRuns)
	}
	stdout := httptest.NewRecorder()
	handler.ServeHTTP(stdout, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/tool-runs/"+runWithLog.ID+"/stdout", nil))
	if stdout.Code != http.StatusOK {
		t.Fatalf("stdout status = %d body=%s", stdout.Code, stdout.Body.String())
	}
	missingLog := httptest.NewRecorder()
	handler.ServeHTTP(missingLog, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/tool-runs/not-a-run/stdout", nil))
	if missingLog.Code != http.StatusNotFound || !strings.Contains(missingLog.Body.String(), "log file not available") {
		t.Fatalf("missing log status = %d body=%s", missingLog.Code, missingLog.Body.String())
	}

	stats := httptest.NewRecorder()
	handler.ServeHTTP(stats, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/stats", nil))
	if stats.Code != http.StatusOK {
		t.Fatalf("stats status = %d", stats.Code)
	}

	vectors := httptest.NewRecorder()
	handler.ServeHTTP(vectors, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/vectors", nil))
	if vectors.Code != http.StatusOK {
		t.Fatalf("vectors status = %d", vectors.Code)
	}

	cves := httptest.NewRecorder()
	handler.ServeHTTP(cves, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/cves", nil))
	if cves.Code != http.StatusOK {
		t.Fatalf("cves status = %d", cves.Code)
	}

	report := httptest.NewRecorder()
	handler.ServeHTTP(report, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/report?format=md&mode=technical", nil))
	if report.Code != http.StatusOK || !strings.Contains(report.Body.String(), "Executive Summary") {
		t.Fatalf("report status = %d body=%s", report.Code, report.Body.String())
	}

	history := httptest.NewRecorder()
	handler.ServeHTTP(history, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/llm/history", nil))
	if history.Code != http.StatusOK {
		t.Fatalf("llm history status = %d", history.Code)
	}

	analyse := httptest.NewRecorder()
	handler.ServeHTTP(analyse, jsonRequest(http.MethodPost, "/api/sessions/"+created.Session.ID+"/llm/analyse", nil))
	if analyse.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable llm status, got %d", analyse.Code)
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/sessions/not-found", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}

	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/sessions/"+created.Session.ID, nil))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestCompareSessionsReportsRetestDiff(t *testing.T) {
	ctx := context.Background()
	sessionDir := t.TempDir()
	now := time.Now().UTC()
	baseSession := models.Session{ID: "base-session", Name: "Original", Status: models.SessionStatusCompleted, TargetInput: "https://app.test", TargetCount: 1, CreatedAt: now}
	retestSession := models.Session{ID: "retest-session", Name: "Retest", Status: models.SessionStatusCompleted, TargetInput: "https://app.test", TargetCount: 1, CreatedAt: now.Add(time.Minute)}
	baseTarget := models.Target{ID: "base-target", SessionID: baseSession.ID, Host: "app.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: now}
	retestTarget := models.Target{ID: "retest-target", SessionID: retestSession.ID, Host: "app.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: now}
	if _, err := db.CreateSessionDB(ctx, sessionDir, baseSession, baseTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSessionDB(ctx, sessionDir, retestSession, retestTarget); err != nil {
		t.Fatal(err)
	}
	baseStore, err := db.OpenSession(ctx, sessionDir, baseSession.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer baseStore.Close()
	retestStore, err := db.OpenSession(ctx, sessionDir, retestSession.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer retestStore.Close()
	for _, finding := range []models.Finding{
		{ID: "same-base", SessionID: baseSession.ID, TargetID: baseTarget.ID, ToolID: "scanner", Type: models.FindingTypeVulnerability, Severity: models.SeverityHigh, Title: "Reflected XSS", URL: "https://app.test/search", CreatedAt: now},
		{ID: "resolved-base", SessionID: baseSession.ID, TargetID: baseTarget.ID, ToolID: "scanner", Type: models.FindingTypeMisconfiguration, Severity: models.SeverityMedium, Title: "Missing CSP", URL: "https://app.test", CreatedAt: now},
	} {
		if err := baseStore.InsertFinding(ctx, finding); err != nil {
			t.Fatal(err)
		}
	}
	for _, finding := range []models.Finding{
		{ID: "same-retest", SessionID: retestSession.ID, TargetID: retestTarget.ID, ToolID: "scanner", Type: models.FindingTypeVulnerability, Severity: models.SeverityCritical, Title: "Reflected XSS", URL: "https://app.test/search", CreatedAt: now},
		{ID: "new-retest", SessionID: retestSession.ID, TargetID: retestTarget.ID, ToolID: "scanner", Type: models.FindingTypeExposure, Severity: models.SeverityLow, Title: "Debug endpoint", URL: "https://app.test/debug", CreatedAt: now},
	} {
		if err := retestStore.InsertFinding(ctx, finding); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewServer(Config{SessionDir: sessionDir}).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions/"+retestSession.ID+"/compare?base="+baseSession.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("compare status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result sessionCompareResponse
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.NewCount != 1 || result.ResolvedCount != 1 || result.SeverityChangeCount != 1 {
		t.Fatalf("unexpected compare result: %#v", result)
	}
	if result.SeverityChanges[0].From != models.SeverityHigh || result.SeverityChanges[0].To != models.SeverityCritical {
		t.Fatalf("unexpected severity change: %#v", result.SeverityChanges[0])
	}
}

func TestLLMHistoryIsCappedAndPageable(t *testing.T) {
	ctx := context.Background()
	sessionDir := t.TempDir()
	session := models.Session{
		ID:          models.NewID(),
		Status:      models.SessionStatusCompleted,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.test",
		InScope:     []string{"https://example.test"},
		CreatedAt:   time.Now().UTC(),
	}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "example.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: time.Now().UTC()}
	if _, err := db.CreateSessionDB(ctx, sessionDir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, sessionDir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 205; i++ {
		analysis := models.LLMAnalysis{
			ID:            models.NewID(),
			SessionID:     session.ID,
			ModelID:       "fixture-model",
			PromptSummary: "analysis-" + strconv.Itoa(i),
			Messages:      []models.LLMMessage{{Role: "assistant", Content: "result"}},
			CreatedAt:     base.Add(time.Duration(i) * time.Second),
		}
		if err := store.InsertLLMAnalysis(ctx, analysis); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	handler := NewServer(Config{SessionDir: sessionDir}).Handler()

	defaultPage := requestLLMHistory(t, handler, session.ID, "")
	if len(defaultPage) != defaultLLMHistoryLimit {
		t.Fatalf("default history length = %d, want %d", len(defaultPage), defaultLLMHistoryLimit)
	}
	if defaultPage[0].PromptSummary != "analysis-105" || defaultPage[len(defaultPage)-1].PromptSummary != "analysis-204" {
		t.Fatalf("unexpected default page bounds: %s ... %s", defaultPage[0].PromptSummary, defaultPage[len(defaultPage)-1].PromptSummary)
	}

	cappedPage := requestLLMHistory(t, handler, session.ID, "?limit=500")
	if len(cappedPage) != maxLLMHistoryLimit {
		t.Fatalf("capped history length = %d, want %d", len(cappedPage), maxLLMHistoryLimit)
	}
	if cappedPage[0].PromptSummary != "analysis-5" || cappedPage[len(cappedPage)-1].PromptSummary != "analysis-204" {
		t.Fatalf("unexpected capped page bounds: %s ... %s", cappedPage[0].PromptSummary, cappedPage[len(cappedPage)-1].PromptSummary)
	}

	offsetPage := requestLLMHistory(t, handler, session.ID, "?limit=3&offset=2")
	if got := llmAnalysisSummaries(offsetPage); strings.Join(got, ",") != "analysis-200,analysis-201,analysis-202" {
		t.Fatalf("unexpected offset page: %#v", got)
	}

	for _, query := range []string{"?limit=0", "?limit=abc", "?offset=-1"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions/"+session.ID+"/llm/history"+query, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query %s status = %d body=%s", query, rec.Code, rec.Body.String())
		}
	}
}

func TestAPIKeyAuth(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", blocked.Code)
	}
	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Nyx-API-Key", "secret")
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected authorized health, got %d", allowed.Code)
	}
	queryToken := httptest.NewRecorder()
	handler.ServeHTTP(queryToken, httptest.NewRequest(http.MethodGet, "/api/health?api_key=secret", nil))
	if queryToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected query-string api key rejection, got %d", queryToken.Code)
	}
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, jsonRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"api_key":"secret"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authSessionCookieName || cookies[0].Value == "" || !cookies[0].HttpOnly {
		t.Fatalf("expected opaque HttpOnly auth cookie, got %#v", cookies)
	}
	cookieAllowed := httptest.NewRecorder()
	cookieReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	cookieReq.AddCookie(cookies[0])
	handler.ServeHTTP(cookieAllowed, cookieReq)
	if cookieAllowed.Code != http.StatusOK {
		t.Fatalf("expected cookie-authenticated health, got %d", cookieAllowed.Code)
	}
	logout := httptest.NewRecorder()
	logoutReq := jsonRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.AddCookie(cookies[0])
	handler.ServeHTTP(logout, logoutReq)
	if logout.Code != http.StatusOK {
		t.Fatalf("expected logout success, got %d", logout.Code)
	}
	afterLogout := httptest.NewRecorder()
	afterLogoutReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	afterLogoutReq.AddCookie(cookies[0])
	handler.ServeHTTP(afterLogout, afterLogoutReq)
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("expected logged-out cookie rejection, got %d", afterLogout.Code)
	}
	for i := 0; i < authFailureLimit; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	}
	limited := httptest.NewRecorder()
	handler.ServeHTTP(limited, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected auth failure rate limit, got %d", limited.Code)
	}
}

func TestAuthCookieSecureConfig(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret", SecureCookies: true}).Handler()
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, jsonRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"api_key":"secret"}`)))
	if login.Code != http.StatusOK {
		t.Fatalf("expected login success, got %d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("expected secure auth cookie, got %#v", cookies)
	}
}

func TestAuthLoginFailsWhenSessionTokenCannotBeGenerated(t *testing.T) {
	previous := newAuthSessionID
	newAuthSessionID = func() (string, error) {
		return "", errors.New("entropy unavailable")
	}
	defer func() {
		newAuthSessionID = previous
	}()

	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, jsonRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"api_key":"secret"}`)))
	if login.Code != http.StatusInternalServerError {
		t.Fatalf("expected session token failure, got %d body=%s", login.Code, login.Body.String())
	}
	if cookies := login.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no auth cookie on token generation failure, got %#v", cookies)
	}
}

func TestAuthSessionPruningRemovesOnlyExpiredSessions(t *testing.T) {
	server := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"})
	now := time.Now()
	server.authSessionMu.Lock()
	server.authSessions["expired"] = now.Add(-time.Second)
	server.authSessions["active"] = now.Add(time.Hour)
	server.authSessionMu.Unlock()

	if pruned := server.pruneExpiredAuthSessions(now); pruned != 1 {
		t.Fatalf("expected one expired auth session pruned, got %d", pruned)
	}
	server.authSessionMu.Lock()
	defer server.authSessionMu.Unlock()
	if _, ok := server.authSessions["expired"]; ok {
		t.Fatal("expired auth session was not removed")
	}
	if _, ok := server.authSessions["active"]; !ok {
		t.Fatal("active auth session was removed")
	}
}

func TestAuthFailureBackoffEscalatesAndResetsOnSuccess(t *testing.T) {
	server := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"})
	now := time.Now()
	keys := []string{"client:127.0.0.1", "credential:" + authSecretFingerprint("bad-secret")}

	for i := 0; i < authFailureLimit; i++ {
		if server.authLimitedAt(now, keys...) {
			t.Fatal("auth should not be limited before threshold is recorded")
		}
		server.recordAuthFailureAt(now, keys...)
	}
	if !server.authLimitedAt(now.Add(time.Second), keys...) {
		t.Fatal("expected auth to be limited after threshold failures")
	}
	server.authFailureMu.Lock()
	firstLockout := server.authFailures[keys[0]].LockedUntil
	server.authFailureMu.Unlock()
	server.recordAuthFailureAt(firstLockout.Add(time.Second), keys...)
	server.authFailureMu.Lock()
	secondLockout := server.authFailures[keys[0]].LockedUntil
	server.authFailureMu.Unlock()
	if !secondLockout.After(firstLockout.Add(authLockoutBase)) {
		t.Fatalf("expected later failures to increase lockout, first=%s second=%s", firstLockout, secondLockout)
	}

	server.clearAuthFailures(keys...)
	if server.authLimitedAt(secondLockout, keys...) {
		t.Fatal("successful auth should clear accumulated lockout state")
	}
}

func TestAuthLockoutDurationCapsLargeCounts(t *testing.T) {
	if got := authLockoutDuration(authFailureLimit - 1); got != 0 {
		t.Fatalf("expected no lockout below failure limit, got %s", got)
	}
	if got := authLockoutDuration(authFailureLimit); got != authLockoutBase {
		t.Fatalf("expected base lockout at failure limit, got %s", got)
	}
	maxInt := int(^uint(0) >> 1)
	if got := authLockoutDuration(maxInt); got != authLockoutMax {
		t.Fatalf("expected maximum lockout for pathological count, got %s", got)
	}
}

func TestAuthFailurePruningRemovesIdleUnlockedRecords(t *testing.T) {
	server := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"})
	now := time.Now()
	server.authFailureMu.Lock()
	server.authFailures["old"] = authFailureState{Count: 2, LastFailure: now.Add(-authFailureIdleReset - time.Second)}
	server.authFailures["locked"] = authFailureState{Count: authFailureLimit, LastFailure: now.Add(-authFailureIdleReset - time.Second), LockedUntil: now.Add(time.Minute)}
	server.authFailureMu.Unlock()

	if pruned := server.pruneStaleAuthFailures(now); pruned != 1 {
		t.Fatalf("expected one stale auth failure record pruned, got %d", pruned)
	}
	server.authFailureMu.Lock()
	defer server.authFailureMu.Unlock()
	if _, ok := server.authFailures["old"]; ok {
		t.Fatal("stale unlocked auth failure record was not removed")
	}
	if _, ok := server.authFailures["locked"]; !ok {
		t.Fatal("active lockout record was removed")
	}
}

func TestStartScanRejectsUnsafeExtraArgs(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	body := bytes.NewBufferString(`{"target":"http://127.0.0.1:1","tools":["sqlmap"],"tool_parameters":{"sqlmap":{"extra_args":["--os-shell"]}}}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, jsonRequest(http.MethodPost, "/api/scan/start", body))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "safe allow-list") {
		t.Fatalf("expected unsafe extra args rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrivilegedOperationsRequireConfiguredAPIKey(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("api_key = \"FAKE_SECRET\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{SessionDir: t.TempDir()})
	if err := server.writeGlobalPlugins([]models.PluginRecord{{
		ID:      "plugin-1",
		Name:    "existing",
		Binary:  "sh",
		Phase:   "recon",
		Enabled: true,
	}}); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "global plugin create", method: http.MethodPost, path: "/api/plugins", body: `{"name":"poc","binary":"sh","phase":"recon"}`},
		{name: "plugin upload", method: http.MethodPost, path: "/api/plugins/upload", body: ""},
		{name: "llm probe", method: http.MethodPost, path: "/api/llm/models", body: `{"base_url":"http://127.0.0.1:11434"}`},
		{name: "source scan", method: http.MethodPost, path: "/api/scan/start", body: `{"source_path":"` + repo + `"}`},
		{name: "plugin scan", method: http.MethodPost, path: "/api/scan/start", body: `{"target":"http://127.0.0.1:1","tools":["plugin:poc"]}`},
		{name: "default scan with existing global plugin", method: http.MethodPost, path: "/api/scan/start", body: `{"target":"http://127.0.0.1:1"}`},
		{name: "power callback record", method: http.MethodGet, path: "/api/sessions/session-1/callbacks/token-1", body: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, jsonRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected forbidden, got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

}

func TestLLMModelsDoesNotReflectUpstreamErrorBody(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal-secret-token", http.StatusInternalServerError)
	}))
	defer targetServer.Close()
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret", HTTPClient: targetServer.Client(), LLMAllowedHosts: []string{"127.0.0.1"}}).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiKeyRequest(http.MethodPost, "/api/llm/models", bytes.NewBufferString(`{"base_url":"`+targetServer.URL+`"}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected bad gateway, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "internal-secret-token") {
		t.Fatalf("upstream response body leaked: %s", rec.Body.String())
	}
}

func TestLLMModelsHonorsHostAllowlist(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"llama"}]}`))
	}))
	defer targetServer.Close()
	handler := NewServer(Config{
		SessionDir:      t.TempDir(),
		APIKey:          "secret",
		HTTPClient:      targetServer.Client(),
		LLMAllowedHosts: []string{"llm.internal.example"},
	}).Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiKeyRequest(http.MethodPost, "/api/llm/models", bytes.NewBufferString(`{"base_url":"`+targetServer.URL+`"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected allowlist rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, apiKeyRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"http://127.0.0.1:1","llm_base_url":"`+targetServer.URL+`/v1","llm_model":"llama"}`)))
	if start.Code != http.StatusBadRequest {
		t.Fatalf("expected scan LLM URL allowlist rejection, got %d body=%s", start.Code, start.Body.String())
	}
}

func TestLLMChatHonorsHostAllowlistForPersistedSessions(t *testing.T) {
	ctx := t.Context()
	sessionDir := t.TempDir()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "LLM",
		Status:      models.SessionStatusCompleted,
		Mode:        models.ScanModeActive,
		TargetInput: "http://127.0.0.1:1",
		InScope:     []string{"http://127.0.0.1:1"},
		LLMBaseURL:  "http://127.0.0.1:1234/v1",
		LLMModel:    "local",
		CreatedAt:   time.Now().UTC(),
	}
	if _, err := db.CreateSessionDBWithTargets(ctx, sessionDir, session, nil); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{SessionDir: sessionDir, APIKey: "secret", LLMAllowedHosts: []string{"llm.internal.example"}}).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/llm/chat", bytes.NewBufferString(`{"message":"summarize"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected persisted LLM URL allowlist rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadLimitedBodyRejectsOversizedRequests(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcdef"))
	if _, ok := readLimitedBody(rec, req, 3); ok {
		t.Fatal("expected oversized request to be rejected")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServerRejectsUnauthenticatedNetworkBind(t *testing.T) {
	server := NewServer(Config{Host: "0.0.0.0", Port: 0, SessionDir: t.TempDir()})
	if err := server.validateExposure(); err == nil {
		t.Fatal("expected network bind without API key to be rejected")
	}
	server.cfg.APIKey = "secret"
	if err := server.validateExposure(); err != nil {
		t.Fatalf("expected API-key-protected network bind to be allowed: %v", err)
	}
}

func TestHTTPServerSetsConnectionTimeouts(t *testing.T) {
	server := NewServer(Config{Host: "127.0.0.1", Port: 6767, SessionDir: t.TempDir()}).httpServer()
	if server.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Fatalf("expected read header timeout %s, got %s", serverReadHeaderTimeout, server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != serverReadTimeout {
		t.Fatalf("expected read timeout %s, got %s", serverReadTimeout, server.ReadTimeout)
	}
	if server.IdleTimeout != serverIdleTimeout {
		t.Fatalf("expected idle timeout %s, got %s", serverIdleTimeout, server.IdleTimeout)
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("expected write timeout to remain unset for WebSocket support, got %s", server.WriteTimeout)
	}
}

func TestStreamingRouteBypassesNonStreamingTimeout(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/api/scan/session-1/events", want: true},
		{path: "/ws/scan/session-1", want: true},
		{path: "/api/scan/session-1/status", want: false},
		{path: "/api/sessions/session-1/report", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if got := streamingRoute(req); got != tc.want {
				t.Fatalf("streamingRoute(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestSourcePathHonorsAllowlist(t *testing.T) {
	repo := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("@app.get(\"/\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret", SourceRoots: []string{other}}).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiKeyRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"source_path":"`+repo+`"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected source allowlist rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSourceBrowseEndpointsConstrainDirectoryListing(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "repo")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("do-not-expose"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	resolvedRoot, ok := canonicalExistingDir(root)
	if !ok {
		t.Fatal("expected test root to resolve")
	}
	resolvedChild, ok := canonicalExistingDir(child)
	if !ok {
		t.Fatal("expected test child to resolve")
	}
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret", SourceRoots: []string{root}}).Handler()

	roots := httptest.NewRecorder()
	handler.ServeHTTP(roots, apiKeyRequest(http.MethodGet, "/api/source-roots", nil))
	if roots.Code != http.StatusOK {
		t.Fatalf("expected source roots, got %d body=%s", roots.Code, roots.Body.String())
	}
	var rootResponse sourceRootResponse
	if err := json.NewDecoder(roots.Body).Decode(&rootResponse); err != nil {
		t.Fatal(err)
	}
	if len(rootResponse.Roots) != 1 || rootResponse.Roots[0].Path != resolvedRoot {
		t.Fatalf("unexpected roots: %#v", rootResponse.Roots)
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, apiKeyRequest(http.MethodGet, "/api/source-dirs?path="+url.QueryEscape(root), nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected directory listing, got %d body=%s", list.Code, list.Body.String())
	}
	var dirResponse sourceDirResponse
	if err := json.NewDecoder(list.Body).Decode(&dirResponse); err != nil {
		t.Fatal(err)
	}
	if dirResponse.Path != resolvedRoot || dirResponse.ParentPath != "" {
		t.Fatalf("unexpected directory metadata: %#v", dirResponse)
	}
	if len(dirResponse.Directories) != 1 || dirResponse.Directories[0].Name != "repo" || dirResponse.Directories[0].Path != resolvedChild {
		t.Fatalf("expected only child directories, got %#v", dirResponse.Directories)
	}
	if strings.Contains(list.Body.String(), "secret.txt") || strings.Contains(list.Body.String(), "do-not-expose") {
		t.Fatalf("directory listing exposed file data: %s", list.Body.String())
	}

	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, apiKeyRequest(http.MethodGet, "/api/source-dirs?path="+url.QueryEscape(other), nil))
	if blocked.Code != http.StatusBadRequest {
		t.Fatalf("expected outside-root rejection, got %d body=%s", blocked.Code, blocked.Body.String())
	}
}

func TestCrossOriginStateChangingRequestsRejected(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", strings.NewReader(`{"target":"http://127.0.0.1:1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin request rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestStateChangingAPIRequiresJSONContentType(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins", strings.NewReader(`{"name":"poc","binary":"sh","phase":"recon"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected missing content type rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
	form := httptest.NewRequest(http.MethodPost, "/api/plugins", strings.NewReader("name=poc&binary=sh&phase=recon"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formRec := httptest.NewRecorder()
	handler.ServeHTTP(formRec, form)
	if formRec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected form content type rejection, got %d body=%s", formRec.Code, formRec.Body.String())
	}
	jsonReq := httptest.NewRequest(http.MethodPost, "/api/plugins", strings.NewReader(`{"name":"poc","binary":"sh","phase":"recon"}`))
	jsonReq.Header.Set("Content-Type", "application/json")
	jsonRec := httptest.NewRecorder()
	handler.ServeHTTP(jsonRec, jsonReq)
	if jsonRec.Code == http.StatusUnsupportedMediaType {
		t.Fatalf("expected JSON request to pass content type gate, got %d body=%s", jsonRec.Code, jsonRec.Body.String())
	}
}

func TestMonitorConfigAPIRequiresConfiguredAPIKeyAndRedactsSecrets(t *testing.T) {
	withoutKey := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	blocked := httptest.NewRecorder()
	withoutKey.ServeHTTP(blocked, jsonRequest(http.MethodPost, "/api/monitor/configs", bytes.NewBufferString(`{"target_input":"http://127.0.0.1:1","schedule":"@daily"}`)))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("expected monitor writes to require configured API key, got %d body=%s", blocked.Code, blocked.Body.String())
	}

	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, apiKeyRequest(http.MethodPost, "/api/monitor/configs", bytes.NewBufferString(`{"name":"bad","target_input":"http://127.0.0.1:1","schedule":"@daily","enabled_tools":["sqlmap"],"tool_parameters":{"sqlmap":{"extra_args":["--os-shell"]}}}`)))
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "safe allow-list") {
		t.Fatalf("expected unsafe monitor extra args rejection, got %d body=%s", invalid.Code, invalid.Body.String())
	}
	create := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"fixture","target_input":"http://127.0.0.1:1","schedule":"@daily","notification_config":{"slack_webhook_url":"https://hooks.slack.test/secret"}}`)
	handler.ServeHTTP(create, apiKeyRequest(http.MethodPost, "/api/monitor/configs", body))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var config models.MonitorConfig
	if err := json.NewDecoder(create.Body).Decode(&config); err != nil {
		t.Fatal(err)
	}
	if config.NotificationConfig.SlackWebhookURL != "********" {
		t.Fatalf("expected redacted webhook, got %#v", config.NotificationConfig)
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, apiKeyRequest(http.MethodGet, "/api/monitor/configs", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "hooks.slack.test") {
		t.Fatalf("expected redacted monitor list, status=%d body=%s", list.Code, list.Body.String())
	}
}

func TestMonitorBaselineResetUsesCompletedRunSession(t *testing.T) {
	ctx := t.Context()
	sessionDir := t.TempDir()
	handler := NewServer(Config{SessionDir: sessionDir, APIKey: "secret"}).Handler()
	create := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"fixture","target_input":"http://127.0.0.1:1","schedule":"@daily"}`)
	handler.ServeHTTP(create, apiKeyRequest(http.MethodPost, "/api/monitor/configs", body))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var config models.MonitorConfig
	if err := json.NewDecoder(create.Body).Decode(&config); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, state.DBPath(sessionDir))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	completedAt := time.Now().UTC()
	run := models.MonitorRun{
		ID:           "run-1",
		ConfigID:     config.ID,
		SessionID:    "session-1",
		Status:       models.MonitorRunStatusCompleted,
		ChangesFound: true,
		StartedAt:    completedAt.Add(-time.Minute),
		CompletedAt:  &completedAt,
	}
	if err := store.InsertMonitorRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	reset := httptest.NewRecorder()
	handler.ServeHTTP(reset, apiKeyRequest(http.MethodPost, "/api/monitor/configs/"+config.ID+"/baseline", bytes.NewBufferString(`{"run_id":"run-1"}`)))
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status=%d body=%s", reset.Code, reset.Body.String())
	}
	var updated models.MonitorConfig
	if err := json.NewDecoder(reset.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.BaselineSessionID != "session-1" {
		t.Fatalf("expected baseline to use completed run session, got %q", updated.BaselineSessionID)
	}
}

func TestPowerFeatureEndpointsPersistAndGateActiveActions(t *testing.T) {
	ctx := t.Context()
	sessionDir := t.TempDir()
	var credentialLoginAttempts int
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			credentialLoginAttempts++
			_ = r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "password" {
				_, _ = w.Write([]byte("success welcome dashboard"))
				return
			}
			http.Error(w, "invalid", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("reflected " + r.URL.Query().Get("q")))
	}))
	defer targetServer.Close()
	parsedTarget, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Power",
		Status:      models.SessionStatusCompleted,
		Mode:        models.ScanModeActive,
		TargetInput: targetServer.URL,
		InScope:     []string{targetServer.URL},
		CreatedAt:   time.Now().UTC(),
	}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: parsedTarget.Hostname(), Port: 80, Protocol: "http", IsAlive: true, CreatedAt: time.Now().UTC()}
	if _, err := db.CreateSessionDB(ctx, sessionDir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, sessionDir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityHigh, Title: "Reflected XSS", URL: targetServer.URL + "/search?q=x", Tags: []string{"xss"}, CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	callback := models.PowerCallback{
		ID:        models.NewID(),
		SessionID: session.ID,
		FindingID: finding.ID,
		Provider:  "builtin",
		Token:     "callback-token",
		URL:       "http://127.0.0.1/callback-token",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.InsertPowerCallback(ctx, callback); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := appconfig.Default()
	cfg.Database.SessionDir = sessionDir
	cfg.Power.ActiveValidation.Enabled = true
	cfg.Power.Credentials.DelaySeconds = 0
	handler := NewServer(Config{SessionDir: sessionDir, APIKey: "secret", AppConfig: cfg, HTTPClient: targetServer.Client()}).Handler()
	payloads := httptest.NewRecorder()
	handler.ServeHTTP(payloads, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/findings/"+finding.ID+"/generate-payloads", bytes.NewBufferString(`{}`)))
	if payloads.Code != http.StatusOK || !strings.Contains(payloads.Body.String(), "confirm") {
		t.Fatalf("payload status=%d body=%s", payloads.Code, payloads.Body.String())
	}
	var generated []models.Payload
	if err := json.NewDecoder(payloads.Body).Decode(&generated); err != nil {
		t.Fatal(err)
	}
	if len(generated) == 0 {
		t.Fatal("expected generated payloads")
	}
	validateBlocked := httptest.NewRecorder()
	handler.ServeHTTP(validateBlocked, jsonRequest(http.MethodPost, "/api/sessions/"+session.ID+"/payloads/"+generated[0].ID+"/validate", bytes.NewBufferString(`{"confirm":true}`)))
	if validateBlocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth on payload validation, got %d body=%s", validateBlocked.Code, validateBlocked.Body.String())
	}
	validateMissingConfirm := httptest.NewRecorder()
	handler.ServeHTTP(validateMissingConfirm, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/payloads/"+generated[0].ID+"/validate", bytes.NewBufferString(`{"confirm":false}`)))
	if validateMissingConfirm.Code != http.StatusBadRequest || !strings.Contains(validateMissingConfirm.Body.String(), "confirm=true") {
		t.Fatalf("expected confirmation rejection, got %d body=%s", validateMissingConfirm.Code, validateMissingConfirm.Body.String())
	}
	validateOK := httptest.NewRecorder()
	handler.ServeHTTP(validateOK, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/payloads/"+generated[0].ID+"/validate", bytes.NewBufferString(`{"confirm":true}`)))
	if validateOK.Code != http.StatusOK || !strings.Contains(validateOK.Body.String(), `"validated":true`) {
		t.Fatalf("expected payload validation success, got %d body=%s", validateOK.Code, validateOK.Body.String())
	}
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, jsonRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"correlate"}`)))
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth on credential action, got %d body=%s", blocked.Code, blocked.Body.String())
	}
	creds := httptest.NewRecorder()
	handler.ServeHTTP(creds, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"correlate","username":"admin","password":"secret"}`)))
	if creds.Code != http.StatusOK || strings.Contains(creds.Body.String(), "secret") {
		t.Fatalf("credential status=%d body=%s", creds.Code, creds.Body.String())
	}
	activeCredsMissing := httptest.NewRecorder()
	handler.ServeHTTP(activeCredsMissing, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"defaults","url":"`+targetServer.URL+`/login","confirm":true,"max_attempts":2}`)))
	if activeCredsMissing.Code != http.StatusBadRequest || !strings.Contains(activeCredsMissing.Body.String(), "explicit username and password") {
		t.Fatalf("expected explicit credential rejection, got %d body=%s", activeCredsMissing.Code, activeCredsMissing.Body.String())
	}
	if credentialLoginAttempts != 0 {
		t.Fatalf("expected no login attempts without explicit credentials, got %d", credentialLoginAttempts)
	}
	activeCreds := httptest.NewRecorder()
	handler.ServeHTTP(activeCreds, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"defaults","url":"`+targetServer.URL+`/login","username":"admin","password":"password","confirm":true,"max_attempts":2}`)))
	if activeCreds.Code != http.StatusOK || !strings.Contains(activeCreds.Body.String(), `"valid":true`) || strings.Contains(activeCreds.Body.String(), `"password":"password"`) {
		t.Fatalf("active credential status=%d body=%s", activeCreds.Code, activeCreds.Body.String())
	}
	kerberoastNoConfirm := httptest.NewRecorder()
	handler.ServeHTTP(kerberoastNoConfirm, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/ad/kerberoast", bytes.NewBufferString(`{"username":"svc-http"}`)))
	if kerberoastNoConfirm.Code != http.StatusBadRequest || !strings.Contains(kerberoastNoConfirm.Body.String(), "confirm=true") {
		t.Fatalf("expected kerberoast confirmation gate, got %d body=%s", kerberoastNoConfirm.Code, kerberoastNoConfirm.Body.String())
	}
	burpBlocked := httptest.NewRecorder()
	handler.ServeHTTP(burpBlocked, jsonRequest(http.MethodPost, "/api/sessions/"+session.ID+"/burp/push-scope", nil))
	if burpBlocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth on burp push-scope, got %d body=%s", burpBlocked.Code, burpBlocked.Body.String())
	}
	callbackBlocked := httptest.NewRecorder()
	handler.ServeHTTP(callbackBlocked, httptest.NewRequest(http.MethodGet, "/api/sessions/"+session.ID+"/callbacks/"+callback.Token, nil))
	if callbackBlocked.Code != http.StatusUnauthorized && callbackBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected auth on callback recording, got %d body=%s", callbackBlocked.Code, callbackBlocked.Body.String())
	}
	callbackOK := httptest.NewRecorder()
	handler.ServeHTTP(callbackOK, apiKeyRequest(http.MethodGet, "/api/sessions/"+session.ID+"/callbacks/"+callback.Token, strings.NewReader("GET /cb?token=secret HTTP/1.1\r\nAuthorization: Bearer top-secret\r\nCookie: session=private\r\n\r\n")))
	if callbackOK.Code != http.StatusOK || !strings.Contains(callbackOK.Body.String(), `"received":true`) {
		t.Fatalf("expected callback record success, got %d body=%s", callbackOK.Code, callbackOK.Body.String())
	}
	callbacks := httptest.NewRecorder()
	handler.ServeHTTP(callbacks, apiKeyRequest(http.MethodGet, "/api/sessions/"+session.ID+"/callbacks", nil))
	if callbacks.Code != http.StatusOK || !strings.Contains(callbacks.Body.String(), `"received":true`) || !strings.Contains(callbacks.Body.String(), "127.0.0.1") {
		t.Fatalf("expected received callback in list, got %d body=%s", callbacks.Code, callbacks.Body.String())
	}
	if strings.Contains(callbacks.Body.String(), "top-secret") || strings.Contains(callbacks.Body.String(), "session=private") || strings.Contains(callbacks.Body.String(), "token=secret") {
		t.Fatalf("expected callback event secrets to be redacted, got %s", callbacks.Body.String())
	}
}

func TestSourceFindingsAndAttackGraphEndpoints(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("@app.get(\"/search\")\ndef search():\n    q = request.args.get(\"q\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, apiKeyRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"source_path":"`+repo+`","name":"Static","mode":"passive"}`)))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resolvedRepo, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	if created.Session.WorkloadMode != models.WorkloadModeStatic || created.Session.SourcePath != resolvedRepo {
		t.Fatalf("unexpected static session: %#v", created.Session)
	}
	waitForCompletedScanWithKey(t, handler, created.Session.ID, "secret")
	sourceFindings := httptest.NewRecorder()
	handler.ServeHTTP(sourceFindings, apiKeyRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/source-findings?kind=route", nil))
	if sourceFindings.Code != http.StatusOK || !strings.Contains(sourceFindings.Body.String(), "/search") {
		t.Fatalf("source findings status=%d body=%s", sourceFindings.Code, sourceFindings.Body.String())
	}
	edges := httptest.NewRecorder()
	handler.ServeHTTP(edges, apiKeyRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/attack-graph-edges", nil))
	if edges.Code != http.StatusOK {
		t.Fatalf("graph edges status=%d body=%s", edges.Code, edges.Body.String())
	}
}

func TestOperatorConsoleAPI(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"llama3:8b"},{"id":"codellama"}]}`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetServer.Close()
	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client(), LLMAllowedHosts: []string{"127.0.0.1"}})
	handler := server.Handler()

	tools := httptest.NewRecorder()
	handler.ServeHTTP(tools, httptest.NewRequest(http.MethodGet, "/api/tools", nil))
	if tools.Code != http.StatusOK {
		t.Fatalf("tools status = %d body=%s", tools.Code, tools.Body.String())
	}
	var records []toolRecord
	if err := json.NewDecoder(tools.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}
	foundFFUF := false
	for _, record := range records {
		if record.ID == "ffuf" {
			foundFFUF = len(record.Parameters) > 0 && record.Kind == "subprocess"
		}
	}
	if !foundFFUF {
		t.Fatalf("expected ffuf tool metadata, got %#v", records)
	}

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","mode":"active","tools":["http-probe"],"tool_parameters":{"ffuf":{"wordlist":"/tmp/words.txt"}},"concurrency":2,"per_tool_concurrency":1,"tool_timeout_seconds":15,"tool_delay_ms":25,"rate_limit":"gentle"}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, jsonRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if len(created.Session.EnabledTools) != 1 || created.Session.EnabledTools[0] != "http-probe" {
		t.Fatalf("expected enabled tools in response, got %#v", created.Session.EnabledTools)
	}
	if created.Session.ToolParameters["ffuf"]["wordlist"] != "/tmp/words.txt" {
		t.Fatalf("expected tool parameters in response, got %#v", created.Session.ToolParameters)
	}
	if created.Session.RunnerOptions.ToolTimeoutSeconds != 15 || created.Session.RunnerOptions.RateLimit != "gentle" {
		t.Fatalf("expected runner options in response, got %#v", created.Session.RunnerOptions)
	}
	waitForCompletedScan(t, handler, created.Session.ID)

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, jsonRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["missing-tool"]}`)))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unknown tool, got %d", bad.Code)
	}

	crtsh := httptest.NewRecorder()
	handler.ServeHTTP(crtsh, jsonRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"http://127.0.0.1","mode":"passive","tools":["crtsh"]}`)))
	if crtsh.Code != http.StatusAccepted {
		t.Fatalf("expected crtsh to be registered, got %d body=%s", crtsh.Code, crtsh.Body.String())
	}
	var crtshCreated db.SessionRecord
	if err := json.NewDecoder(crtsh.Body).Decode(&crtshCreated); err != nil {
		t.Fatal(err)
	}
	waitForCompletedScan(t, handler, crtshCreated.Session.ID)

	multiTarget := httptest.NewRecorder()
	handler.ServeHTTP(multiTarget, jsonRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"targets":["`+targetServer.URL+`","`+strings.Replace(targetServer.URL, "127.0.0.1", "localhost", 1)+`"],"mode":"active","tools":["http-probe"]}`)))
	if multiTarget.Code != http.StatusAccepted {
		t.Fatalf("multi-target start status = %d body=%s", multiTarget.Code, multiTarget.Body.String())
	}
	var multiCreated db.SessionRecord
	if err := json.NewDecoder(multiTarget.Body).Decode(&multiCreated); err != nil {
		t.Fatal(err)
	}
	if multiCreated.Session.TargetCount != 2 {
		t.Fatalf("expected two targets, got %#v", multiCreated.Session)
	}
	waitForCompletedScan(t, handler, multiCreated.Session.ID)

	invalidTarget := httptest.NewRecorder()
	handler.ServeHTTP(invalidTarget, jsonRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"targets":["ftp://example.com"],"mode":"active","tools":["http-probe"]}`)))
	if invalidTarget.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid target rejection, got %d", invalidTarget.Code)
	}

	unsafeArgs := httptest.NewRecorder()
	handler.ServeHTTP(unsafeArgs, jsonRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["ffuf"],"tool_parameters":{"ffuf":{"extra_args":["--output","/tmp/leak"]}}}`)))
	if unsafeArgs.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unsafe extra args, got %d", unsafeArgs.Code)
	}

	profileBody := bytes.NewBufferString(`{"name":"Web active","description":"Saved","request":{"target":"","mode":"active","tools":["http-probe"],"enabled_phases":["fingerprint"],"route_seeds":["/admin"],"auth_headers":{"Authorization":"Bearer secret"},"auth_cookie_header":"session=secret","auth_profile":{"type":"form","username":"alice","password":"secret"}}}`)
	profileCreate := httptest.NewRecorder()
	handler.ServeHTTP(profileCreate, jsonRequest(http.MethodPost, "/api/scan-profiles", profileBody))
	if profileCreate.Code != http.StatusCreated {
		t.Fatalf("profile create status = %d body=%s", profileCreate.Code, profileCreate.Body.String())
	}
	var profile scanProfileRecord
	if err := json.NewDecoder(profileCreate.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Request.RouteSeeds) != 1 || profile.Request.RouteSeeds[0] != "/admin" {
		t.Fatalf("expected route seeds to remain in profile, got %#v", profile.Request.RouteSeeds)
	}
	if len(profile.Request.AuthHeaders) != 0 || profile.Request.AuthCookieHeader != "" || len(profile.Request.AuthProfile) != 0 {
		t.Fatalf("expected auth secrets to be omitted from saved profile, got %#v", profile.Request)
	}
	profileList := httptest.NewRecorder()
	handler.ServeHTTP(profileList, httptest.NewRequest(http.MethodGet, "/api/scan-profiles", nil))
	if profileList.Code != http.StatusOK || !strings.Contains(profileList.Body.String(), profile.ID) {
		t.Fatalf("profile list status = %d body=%s", profileList.Code, profileList.Body.String())
	}
	profileDelete := httptest.NewRecorder()
	handler.ServeHTTP(profileDelete, httptest.NewRequest(http.MethodDelete, "/api/scan-profiles/"+profile.ID, nil))
	if profileDelete.Code != http.StatusOK {
		t.Fatalf("profile delete status = %d body=%s", profileDelete.Code, profileDelete.Body.String())
	}

	server.cfg.APIKey = "secret"
	badPlugin := httptest.NewRecorder()
	handler.ServeHTTP(badPlugin, apiKeyRequest(http.MethodPost, "/api/sessions/"+created.Session.ID+"/plugins", bytes.NewBufferString(`{"binary":"definitely-not-a-real-plugin-binary"}`)))
	if badPlugin.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for missing plugin binary, got %d", badPlugin.Code)
	}

	pluginBinary := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(pluginBinary, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	globalPlugin := httptest.NewRecorder()
	handler.ServeHTTP(globalPlugin, apiKeyRequest(http.MethodPost, "/api/plugins", bytes.NewBufferString(`{"name":"custom-check","binary":"`+pluginBinary+`","phase":"enumerate","description":"custom scanner","homepage_url":"https://example.com","enabled":true}`)))
	if globalPlugin.Code != http.StatusCreated {
		t.Fatalf("global plugin create status = %d body=%s", globalPlugin.Code, globalPlugin.Body.String())
	}
	globalPluginList := httptest.NewRecorder()
	handler.ServeHTTP(globalPluginList, apiKeyRequest(http.MethodGet, "/api/plugins", nil))
	if globalPluginList.Code != http.StatusOK || !strings.Contains(globalPluginList.Body.String(), "custom-check") {
		t.Fatalf("global plugin list status = %d body=%s", globalPluginList.Code, globalPluginList.Body.String())
	}
	toolsWithPlugin := httptest.NewRecorder()
	handler.ServeHTTP(toolsWithPlugin, apiKeyRequest(http.MethodGet, "/api/tools", nil))
	if toolsWithPlugin.Code != http.StatusOK || !strings.Contains(toolsWithPlugin.Body.String(), "plugin:custom-check") {
		t.Fatalf("expected global plugin in tools, got status=%d body=%s", toolsWithPlugin.Code, toolsWithPlugin.Body.String())
	}

	models := httptest.NewRecorder()
	handler.ServeHTTP(models, apiKeyRequest(http.MethodPost, "/api/llm/models", bytes.NewBufferString(`{"base_url":"`+targetServer.URL+`"}`)))
	if models.Code != http.StatusOK || !strings.Contains(models.Body.String(), "llama3:8b") {
		t.Fatalf("models status = %d body=%s", models.Code, models.Body.String())
	}
}

func TestPluginUploadUsesPrivateExecutablePermissions(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("binary", "plugin.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("#!/bin/sh\necho ok\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := apiKeyRequest(http.MethodPost, "/api/plugins/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Binary string `json:"binary"`
		SHA256 string `json:"sha256"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(payload.Binary)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private executable upload mode 0700, got %03o", got)
	}
	uploaded, err := os.ReadFile(payload.Binary) // #nosec G304 -- path is returned by the upload endpoint under the test temp state dir.
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(uploaded)
	if payload.SHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("expected upload sha256 %s, got %s", hex.EncodeToString(wantDigest[:]), payload.SHA256)
	}
	dirInfo, err := os.Stat(filepath.Dir(payload.Binary))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private plugin bin dir mode 0700, got %03o", got)
	}
}

func apiKeyRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("X-Nyx-API-Key", "secret")
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func jsonRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func waitForCompletedScan(t *testing.T, handler http.Handler, sessionID string) {
	t.Helper()
	waitForScanStatus(t, handler, sessionID, models.SessionStatusCompleted)
}

func waitForCompletedScanWithKey(t *testing.T, handler http.Handler, sessionID, apiKey string) {
	t.Helper()
	waitForScanStatusWithKey(t, handler, sessionID, models.SessionStatusCompleted, apiKey)
}

func waitForScanStatus(t *testing.T, handler http.Handler, sessionID string, want models.SessionStatus) {
	t.Helper()
	waitForScanStatusWithKey(t, handler, sessionID, want, "")
}

func waitForScanStatusWithKey(t *testing.T, handler http.Handler, sessionID string, want models.SessionStatus, apiKey string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		status := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/scan/"+sessionID+"/status", nil)
		if apiKey != "" {
			req.Header.Set("X-Nyx-API-Key", apiKey)
		}
		handler.ServeHTTP(status, req)
		if status.Code != http.StatusOK {
			t.Fatalf("scan status = %d", status.Code)
		}
		var payload struct {
			Status models.SessionStatus `json:"status"`
		}
		if err := json.NewDecoder(status.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan did not reach status %s", want)
}

func TestScanEventsWebSocketReplaysLifecycle(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Nyx Test</title>"))
	}))
	defer targetServer.Close()

	handler := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()}).Handler()
	apiServer := httptest.NewServer(handler)
	defer apiServer.Close()

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Events","mode":"active","tools":["http-probe","security-headers"],"tool_timeout_seconds":10}`)
	resp, err := http.Post(apiServer.URL+"/api/scan/start", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	var created db.SessionRecord
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCompleted)

	wsURL := "ws" + strings.TrimPrefix(apiServer.URL, "http") + "/ws/scan/" + created.Session.ID
	crossOriginHeader := http.Header{"Origin": []string{"https://attacker.example"}}
	blockedConn, blockedResp, err := websocket.DefaultDialer.Dial(wsURL, crossOriginHeader)
	if err == nil {
		_ = blockedConn.Close()
		t.Fatal("expected cross-origin websocket dial to fail")
	}
	if blockedResp == nil || blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected websocket 403, got resp=%v err=%v", blockedResp, err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	seen := map[engine.ScanEventType]bool{}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var event engine.ScanEvent
		if err := conn.ReadJSON(&event); err != nil {
			t.Fatalf("read scan event: %v", err)
		}
		seen[event.Type] = true
		if event.Type == engine.ScanEventCompleted || event.Type == engine.ScanEventFailed {
			break
		}
	}
	for _, eventType := range []engine.ScanEventType{
		engine.ScanEventQueued,
		engine.ScanEventRunning,
		engine.ScanEventToolStarted,
		engine.ScanEventToolCompleted,
		engine.ScanEventFindingFound,
		engine.ScanEventCompleted,
	} {
		if !seen[eventType] {
			t.Fatalf("missing event %s; saw %#v", eventType, seen)
		}
	}
}

func TestStopScanCancelsRunningScan(t *testing.T) {
	requestStarted := make(chan struct{})
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer targetServer.Close()

	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()})
	handler := server.Handler()

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Cancel","mode":"active"}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, jsonRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start target request")
	}

	pause := httptest.NewRecorder()
	handler.ServeHTTP(pause, jsonRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/pause", nil))
	if pause.Code != http.StatusAccepted {
		t.Fatalf("pause status = %d body=%s", pause.Code, pause.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusPaused)

	resume := httptest.NewRecorder()
	handler.ServeHTTP(resume, jsonRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/resume", nil))
	if resume.Code != http.StatusAccepted {
		t.Fatalf("resume status = %d body=%s", resume.Code, resume.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusRunning)

	stop := httptest.NewRecorder()
	handler.ServeHTTP(stop, jsonRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/stop", nil))
	if stop.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d body=%s", stop.Code, stop.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCancelled)
}

func TestScanManagerShutdownDrainsRunningScans(t *testing.T) {
	requestStarted := make(chan struct{})
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-requestStarted:
		default:
			close(requestStarted)
		}
		<-r.Context().Done()
	}))
	defer targetServer.Close()
	parsed, err := url.Parse(targetServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	sessionDir := t.TempDir()
	session := models.Session{
		ID:           models.NewID(),
		Name:         "Shutdown",
		Status:       models.SessionStatusPending,
		Mode:         models.ScanModeActive,
		TargetInput:  targetServer.URL,
		InScope:      []string{targetServer.URL},
		EnabledTools: []string{"http-probe"},
		CreatedAt:    time.Now().UTC(),
	}
	target := models.Target{
		ID:        models.NewID(),
		SessionID: session.ID,
		Host:      parsed.Hostname(),
		Port:      port,
		Protocol:  parsed.Scheme,
		CreatedAt: time.Now().UTC(),
	}
	record, err := db.CreateSessionDB(t.Context(), sessionDir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewScanManager(sessionDir, targetServer.Client(), nil)
	manager.Start(record.Session)
	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start target request")
	}
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(t.Context(), sessionDir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.GetSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SessionStatusCancelled {
		t.Fatalf("expected cancelled scan after manager shutdown, got %s", got.Status)
	}
}

func requestLLMHistory(t *testing.T, handler http.Handler, sessionID, query string) []models.LLMAnalysis {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions/"+sessionID+"/llm/history"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("llm history status = %d body=%s", rec.Code, rec.Body.String())
	}
	var analyses []models.LLMAnalysis
	if err := json.NewDecoder(rec.Body).Decode(&analyses); err != nil {
		t.Fatal(err)
	}
	return analyses
}

func llmAnalysisSummaries(analyses []models.LLMAnalysis) []string {
	summaries := make([]string, 0, len(analyses))
	for _, analysis := range analyses {
		summaries = append(summaries, analysis.PromptSummary)
	}
	return summaries
}
