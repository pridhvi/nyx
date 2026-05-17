package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	appconfig "github.com/pridhvi/nox/internal/config"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/engine"
	"github.com/pridhvi/nox/internal/models"
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

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nhealth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Example","mode":"active","out_of_scope":["admin.example.com"],"tools":["http-probe","security-headers","ffuf"],"tool_parameters":{"ffuf":{"wordlist":"` + wordlist + `","timeout_seconds":5}}}`)
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
	queryToken := httptest.NewRecorder()
	handler.ServeHTTP(queryToken, httptest.NewRequest(http.MethodGet, "/api/health?api_key=secret", nil))
	if queryToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected query-string api key rejection, got %d", queryToken.Code)
	}
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"api_key":"secret"}`)))
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
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
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
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret", HTTPClient: targetServer.Client()}).Handler()

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

func TestCrossOriginStateChangingRequestsRejected(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/scan/start", strings.NewReader(`{"target":"http://127.0.0.1:1"}`))
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin request rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMonitorConfigAPIRequiresConfiguredAPIKeyAndRedactsSecrets(t *testing.T) {
	withoutKey := NewServer(Config{SessionDir: t.TempDir()}).Handler()
	blocked := httptest.NewRecorder()
	withoutKey.ServeHTTP(blocked, httptest.NewRequest(http.MethodPost, "/api/monitor/configs", bytes.NewBufferString(`{"target_input":"http://127.0.0.1:1","schedule":"@daily"}`)))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("expected monitor writes to require configured API key, got %d body=%s", blocked.Code, blocked.Body.String())
	}

	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
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

func TestPowerFeatureEndpointsPersistAndGateActiveActions(t *testing.T) {
	ctx := t.Context()
	sessionDir := t.TempDir()
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
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
	handler.ServeHTTP(validateBlocked, httptest.NewRequest(http.MethodPost, "/api/sessions/"+session.ID+"/payloads/"+generated[0].ID+"/validate", bytes.NewBufferString(`{"confirm":true}`)))
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
	handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"correlate"}`)))
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth on credential action, got %d body=%s", blocked.Code, blocked.Body.String())
	}
	creds := httptest.NewRecorder()
	handler.ServeHTTP(creds, apiKeyRequest(http.MethodPost, "/api/sessions/"+session.ID+"/credentials/test", bytes.NewBufferString(`{"mode":"correlate","username":"admin","password":"secret"}`)))
	if creds.Code != http.StatusOK || strings.Contains(creds.Body.String(), "secret") {
		t.Fatalf("credential status=%d body=%s", creds.Code, creds.Body.String())
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
	handler.ServeHTTP(burpBlocked, httptest.NewRequest(http.MethodPost, "/api/sessions/"+session.ID+"/burp/push-scope", nil))
	if burpBlocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth on burp push-scope, got %d body=%s", burpBlocked.Code, burpBlocked.Body.String())
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
	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()})
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
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
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
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["missing-tool"]}`)))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unknown tool, got %d", bad.Code)
	}

	crtsh := httptest.NewRecorder()
	handler.ServeHTTP(crtsh, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"http://127.0.0.1","mode":"passive","tools":["crtsh"]}`)))
	if crtsh.Code != http.StatusAccepted {
		t.Fatalf("expected crtsh to be registered, got %d body=%s", crtsh.Code, crtsh.Body.String())
	}
	var crtshCreated db.SessionRecord
	if err := json.NewDecoder(crtsh.Body).Decode(&crtshCreated); err != nil {
		t.Fatal(err)
	}
	waitForCompletedScan(t, handler, crtshCreated.Session.ID)

	multiTarget := httptest.NewRecorder()
	handler.ServeHTTP(multiTarget, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"targets":["`+targetServer.URL+`","`+strings.Replace(targetServer.URL, "127.0.0.1", "localhost", 1)+`"],"mode":"active","tools":["http-probe"]}`)))
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
	handler.ServeHTTP(invalidTarget, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"targets":["ftp://example.com"],"mode":"active","tools":["http-probe"]}`)))
	if invalidTarget.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid target rejection, got %d", invalidTarget.Code)
	}

	unsafeArgs := httptest.NewRecorder()
	handler.ServeHTTP(unsafeArgs, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["ffuf"],"tool_parameters":{"ffuf":{"extra_args":["--output","/tmp/leak"]}}}`)))
	if unsafeArgs.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unsafe extra args, got %d", unsafeArgs.Code)
	}

	profileBody := bytes.NewBufferString(`{"name":"Web active","description":"Saved","request":{"target":"","mode":"active","tools":["http-probe"],"enabled_phases":["fingerprint"],"route_seeds":["/admin"],"auth_headers":{"Authorization":"Bearer secret"},"auth_cookie_header":"session=secret","auth_profile":{"type":"form","username":"alice","password":"secret"}}}`)
	profileCreate := httptest.NewRecorder()
	handler.ServeHTTP(profileCreate, httptest.NewRequest(http.MethodPost, "/api/scan-profiles", profileBody))
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

func apiKeyRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("X-Nox-API-Key", "secret")
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
			req.Header.Set("X-Nox-API-Key", apiKey)
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
		_, _ = w.Write([]byte("<title>Nox Test</title>"))
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

	pause := httptest.NewRecorder()
	handler.ServeHTTP(pause, httptest.NewRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/pause", nil))
	if pause.Code != http.StatusAccepted {
		t.Fatalf("pause status = %d body=%s", pause.Code, pause.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusPaused)

	resume := httptest.NewRecorder()
	handler.ServeHTTP(resume, httptest.NewRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/resume", nil))
	if resume.Code != http.StatusAccepted {
		t.Fatalf("resume status = %d body=%s", resume.Code, resume.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusRunning)

	stop := httptest.NewRecorder()
	handler.ServeHTTP(stop, httptest.NewRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/stop", nil))
	if stop.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d body=%s", stop.Code, stop.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCancelled)
}
