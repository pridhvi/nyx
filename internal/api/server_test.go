package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

func TestSessionAPI(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Nox Test</title>"))
	}))
	defer targetServer.Close()

	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()})
	handler := server.Handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Example","mode":"active","out_of_scope":["admin.example.com"]}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
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
	for _, toolID := range []string{"http-probe", "security-headers", "nmap", "ffuf"} {
		if !runIDs[toolID] {
			t.Fatalf("expected tool run %s in %#v", toolID, runIDs)
		}
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
	handler.ServeHTTP(analyse, httptest.NewRequest(http.MethodPost, "/api/sessions/"+created.Session.ID+"/llm/analyse", nil))
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

func TestAPIKeyAuth(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", blocked.Code)
	}
	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Nox-API-Key", "secret")
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected authorized health, got %d", allowed.Code)
	}
}

func waitForCompletedScan(t *testing.T, handler http.Handler, sessionID string) {
	t.Helper()
	waitForScanStatus(t, handler, sessionID, models.SessionStatusCompleted)
}

func waitForScanStatus(t *testing.T, handler http.Handler, sessionID string, want models.SessionStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := httptest.NewRecorder()
		handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/scan/"+sessionID+"/status", nil))
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
		_, _ = w.Write([]byte("<title>Nox Test</title>"))
	}))
	defer targetServer.Close()

	apiServer := httptest.NewServer(NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()}).Handler())
	defer apiServer.Close()

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Events","mode":"active"}`)
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

	wsURL := "ws" + strings.TrimPrefix(apiServer.URL, "http") + "/ws/scan/" + created.Session.ID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	seen := map[engine.ScanEventType]bool{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		var event engine.ScanEvent
		if err := conn.ReadJSON(&event); err != nil {
			continue
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
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
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

	stop := httptest.NewRecorder()
	handler.ServeHTTP(stop, httptest.NewRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/stop", nil))
	if stop.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d body=%s", stop.Code, stop.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCancelled)
}
