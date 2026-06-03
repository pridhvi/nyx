package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pridhvi/nyx/internal/activedirectory"
	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/burp"
	appconfig "github.com/pridhvi/nyx/internal/config"
	"github.com/pridhvi/nyx/internal/creds"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/evasion"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/monitor"
	"github.com/pridhvi/nyx/internal/osint"
	"github.com/pridhvi/nyx/internal/payload"
	"github.com/pridhvi/nyx/internal/poc"
	"github.com/pridhvi/nyx/internal/state"
)

type Config struct {
	Host            string
	Port            int
	SessionDir      string
	APIKey          string
	SecureCookies   bool
	HTTPClient      adapters.HTTPDoer
	ToolPaths       map[string]string
	AppConfig       appconfig.Config
	SourceRoots     []string
	LLMAllowedHosts []string
}

type Server struct {
	cfg          Config
	scanManager  *ScanManager
	monitorMu    sync.Mutex
	monitorSched *monitor.Scheduler
	securityMu   sync.Mutex
	authFailures map[string]authFailureState
	authSessions map[string]time.Time
}

const (
	maxBloodHoundImportBytes = 32 << 20
	maxBurpImportBytes       = 32 << 20
	maxPluginUploadBytes     = 64 << 20

	serverReadHeaderTimeout    = 5 * time.Second
	serverReadTimeout          = 30 * time.Second
	serverIdleTimeout          = 2 * time.Minute
	nonStreamingHandlerTimeout = 2 * time.Minute
	serverShutdownTimeout      = 5 * time.Second
	scanManagerShutdownTimeout = 30 * time.Second
)

func NewServer(cfg Config) *Server {
	if cfg.AppConfig.Database.SessionDir == "" {
		cfg.AppConfig = appconfig.Default()
	}
	if cfg.SessionDir == "" {
		cfg.SessionDir = db.DefaultSessionsDir()
	}
	cfg.SessionDir = absolutePath(cfg.SessionDir)
	cfg.AppConfig.Database.SessionDir = cfg.SessionDir
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("NYX_API_KEY")
	}
	cfg.SecureCookies = cfg.SecureCookies || cfg.AppConfig.Server.SecureCookies || envBool("NYX_SECURE_COOKIES")
	cfg.AppConfig.Server.APIKey = cfg.APIKey
	cfg.AppConfig.Server.SecureCookies = cfg.SecureCookies
	cfg.SourceRoots = append(cfg.SourceRoots, splitEnvList(os.Getenv("NYX_SOURCE_ROOTS"))...)
	cfg.LLMAllowedHosts = append(cfg.LLMAllowedHosts, splitEnvList(os.Getenv("NYX_LLM_ALLOWED_HOSTS"))...)
	server := &Server{
		cfg:          cfg,
		scanManager:  NewScanManager(cfg.SessionDir, cfg.HTTPClient, cfg.LLMAllowedHosts),
		authFailures: make(map[string]authFailureState),
		authSessions: make(map[string]time.Time),
	}
	server.scanManager.SetPluginProvider(func() []models.PluginRecord {
		plugins, _ := server.readGlobalPlugins()
		return plugins
	})
	return server
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.validateExposure(); err != nil {
		return err
	}
	stateStore, err := state.Open(ctx, s.stateDBPath())
	if err != nil {
		return err
	}
	defer stateStore.Close()
	scheduler := monitor.NewScheduler(stateStore, s.cfg.SessionDir, s.cfg.HTTPClient)
	s.monitorMu.Lock()
	s.monitorSched = scheduler
	s.monitorMu.Unlock()
	if err := scheduler.Start(ctx); err != nil {
		return err
	}
	s.startAuthSessionCleanup(ctx)
	defer func() {
		scheduler.Stop()
		s.monitorMu.Lock()
		s.monitorSched = nil
		s.monitorMu.Unlock()
	}()
	server := s.httpServer()
	errCh := make(chan error, 1)
	go func() {
		slog.Info("nyx api listening", "address", server.Addr)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		scheduler.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		httpErr := server.Shutdown(shutdownCtx)
		cancel()
		scanCtx, cancel := context.WithTimeout(context.Background(), scanManagerShutdownTimeout)
		scanErr := s.scanManager.Shutdown(scanCtx)
		cancel()
		return errors.Join(httpErr, scanErr)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) validateExposure() error {
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		return nil
	}
	host := strings.TrimSpace(s.cfg.Host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return fmt.Errorf("NYX_API_KEY or server.api_key is required when binding Nyx to a non-loopback interface")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("NYX_API_KEY or server.api_key is required when binding Nyx to %s", host)
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/logout", s.authLogout)
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/tools", s.tools)
	mux.HandleFunc("GET /api/config/effective", s.effectiveConfig)
	mux.HandleFunc("GET /api/source-roots", s.sourceRoots)
	mux.HandleFunc("GET /api/source-dirs", s.sourceDirs)
	mux.HandleFunc("GET /api/scan-profiles", s.listScanProfiles)
	mux.HandleFunc("POST /api/scan-profiles", s.createScanProfile)
	mux.HandleFunc("DELETE /api/scan-profiles/{profile_id}", s.deleteScanProfile)
	mux.HandleFunc("GET /api/plugins", s.listGlobalPlugins)
	mux.HandleFunc("POST /api/plugins", s.createGlobalPlugin)
	mux.HandleFunc("PATCH /api/plugins/{plugin_id}", s.updateGlobalPlugin)
	mux.HandleFunc("DELETE /api/plugins/{plugin_id}", s.deleteGlobalPlugin)
	mux.HandleFunc("POST /api/plugins/upload", s.uploadPluginBinary)
	mux.HandleFunc("POST /api/llm/models", s.llmModels)
	mux.HandleFunc("GET /api/monitor/configs", s.listMonitorConfigs)
	mux.HandleFunc("POST /api/monitor/configs", s.createMonitorConfig)
	mux.HandleFunc("GET /api/monitor/configs/{config_id}", s.getMonitorConfig)
	mux.HandleFunc("PUT /api/monitor/configs/{config_id}", s.updateMonitorConfig)
	mux.HandleFunc("DELETE /api/monitor/configs/{config_id}", s.deleteMonitorConfig)
	mux.HandleFunc("POST /api/monitor/configs/{config_id}/run", s.runMonitorConfig)
	mux.HandleFunc("GET /api/monitor/runs", s.listMonitorRuns)
	mux.HandleFunc("GET /api/monitor/runs/{run_id}/changes", s.listMonitorRunChanges)
	mux.HandleFunc("PUT /api/monitor/changes/{change_id}/alert-sent", s.markMonitorChangeAlerted)
	mux.HandleFunc("GET /api/sessions", s.listSessions)
	mux.HandleFunc("GET /api/sessions/{id}", s.getSession)
	mux.HandleFunc("DELETE /api/sessions/{id}", s.deleteSession)
	mux.HandleFunc("GET /api/sessions/{id}/targets", s.listTargets)
	mux.HandleFunc("GET /api/sessions/{id}/findings", s.listFindings)
	mux.HandleFunc("GET /api/sessions/{id}/source-findings", s.listSourceFindings)
	mux.HandleFunc("PATCH /api/sessions/{id}/findings/{finding_id}", s.updateFinding)
	mux.HandleFunc("POST /api/sessions/{id}/findings/{finding_id}/generate-payloads", s.generatePayloads)
	mux.HandleFunc("GET /api/sessions/{id}/findings/{finding_id}/payloads", s.listFindingPayloads)
	mux.HandleFunc("POST /api/sessions/{id}/findings/{finding_id}/poc/run", s.runPoC)
	mux.HandleFunc("GET /api/sessions/{id}/findings/{finding_id}/poc", s.listFindingPoCResults)
	mux.HandleFunc("GET /api/sessions/{id}/payloads", s.listSessionPayloads)
	mux.HandleFunc("POST /api/sessions/{id}/payloads/{payload_id}/validate", s.validatePayload)
	mux.HandleFunc("GET /api/sessions/{id}/credentials", s.listCredentials)
	mux.HandleFunc("GET /api/sessions/{id}/credentials/{credential_id}", s.getCredential)
	mux.HandleFunc("POST /api/sessions/{id}/credentials/test", s.testCredentials)
	mux.HandleFunc("POST /api/sessions/{id}/credentials/{credential_id}/redact", s.redactCredential)
	mux.HandleFunc("GET /api/sessions/{id}/osint", s.listOSINTFindings)
	mux.HandleFunc("POST /api/sessions/{id}/osint/run", s.runOSINT)
	mux.HandleFunc("POST /api/sessions/{id}/osint/{finding_id}/seed", s.seedOSINTFinding)
	mux.HandleFunc("GET /api/sessions/{id}/ad/entities", s.listADEntities)
	mux.HandleFunc("GET /api/sessions/{id}/ad/relationships", s.listADRelationships)
	mux.HandleFunc("GET /api/sessions/{id}/ad/artifacts", s.listADArtifacts)
	mux.HandleFunc("POST /api/sessions/{id}/ad/enum", s.runADEnum)
	mux.HandleFunc("POST /api/sessions/{id}/ad/kerberoast", s.runADKerberoast)
	mux.HandleFunc("POST /api/sessions/{id}/ad/bloodhound/import", s.importBloodHound)
	mux.HandleFunc("GET /api/sessions/{id}/ad/bloodhound/export", s.exportBloodHound)
	mux.HandleFunc("GET /api/sessions/{id}/block-events", s.listBlockEvents)
	mux.HandleFunc("GET /api/sessions/{id}/provider-statuses", s.listProviderStatuses)
	mux.HandleFunc("GET /api/sessions/{id}/callbacks", s.listPowerCallbacks)
	mux.HandleFunc("GET /api/sessions/{id}/callbacks/{token}", s.recordPowerCallback)
	mux.HandleFunc("GET /api/sessions/{id}/poc-results", s.listPoCResults)
	mux.HandleFunc("GET /api/sessions/{id}/burp/export/scope", s.exportBurpScope)
	mux.HandleFunc("GET /api/sessions/{id}/burp/export/findings", s.exportBurpFindings)
	mux.HandleFunc("POST /api/sessions/{id}/burp/import", s.importBurpXML)
	mux.HandleFunc("GET /api/sessions/{id}/burp/status", s.burpStatus)
	mux.HandleFunc("POST /api/sessions/{id}/burp/push-scope", s.pushBurpScope)
	mux.HandleFunc("POST /api/sessions/{id}/burp/pull-issues", s.pullBurpIssues)
	mux.HandleFunc("GET /api/sessions/{id}/tool-runs", s.listToolRuns)
	mux.HandleFunc("GET /api/sessions/{id}/tool-runs/{run_id}/stdout", s.toolRunLog("stdout"))
	mux.HandleFunc("GET /api/sessions/{id}/tool-runs/{run_id}/stderr", s.toolRunLog("stderr"))
	mux.HandleFunc("GET /api/sessions/{id}/plugins", s.listPlugins)
	mux.HandleFunc("POST /api/sessions/{id}/plugins", s.upsertPlugin)
	mux.HandleFunc("PATCH /api/sessions/{id}/plugins/{plugin_id}", s.updatePlugin)
	mux.HandleFunc("GET /api/sessions/{id}/stats", s.sessionStats)
	mux.HandleFunc("GET /api/sessions/{id}/vectors", s.listAttackVectors)
	mux.HandleFunc("GET /api/sessions/{id}/attack-graph-edges", s.listAttackGraphEdges)
	mux.HandleFunc("GET /api/sessions/{id}/cves", s.listCVEs)
	mux.HandleFunc("GET /api/sessions/{id}/report", s.generateReport)
	mux.HandleFunc("POST /api/sessions/{id}/llm/chat", s.llmChat)
	mux.HandleFunc("POST /api/sessions/{id}/llm/analyse", s.llmAnalyse)
	mux.HandleFunc("GET /api/sessions/{id}/llm/history", s.llmHistory)
	mux.HandleFunc("GET /api/scan/{id}/status", s.scanStatus)
	mux.HandleFunc("GET /api/scan/{id}/events", s.scanEvents)
	mux.HandleFunc("GET /ws/scan/{id}", s.scanEvents)
	mux.HandleFunc("POST /api/scan/start", s.startScan)
	mux.HandleFunc("POST /api/scan/{id}/stop", s.stopScan)
	mux.HandleFunc("POST /api/scan/{id}/pause", s.pauseScan)
	mux.HandleFunc("POST /api/scan/{id}/resume", s.resumeScan)
	mux.HandleFunc("GET /api/burp/status", s.burpStatus)
	mux.HandleFunc("POST /api/burp/collaborator/setup", s.setupBurpCollaborator)
	mux.HandleFunc("GET /api/burp/collaborator/callbacks", s.listBurpCallbacks)
	mux.Handle("/", spaHandler())
	return timeoutNonStreaming(s.withAuth(mux))
}

func (s *Server) httpServer() *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
}

func timeoutNonStreaming(next http.Handler) http.Handler {
	timeout := http.TimeoutHandler(next, nonStreamingHandlerTimeout, `{"error":"request timed out"}`+"\n")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if streamingRoute(r) {
			next.ServeHTTP(w, r)
			return
		}
		timeout.ServeHTTP(w, r)
	})
}

func streamingRoute(r *http.Request) bool {
	path := strings.TrimSpace(r.URL.Path)
	if strings.HasPrefix(path, "/ws/scan/") {
		return true
	}
	return strings.HasPrefix(path, "/api/scan/") && strings.HasSuffix(path, "/events")
}

func spaHandler() http.Handler {
	dist, err := fs.Sub(webAssets, "web/dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "embedded web assets are unavailable", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(dist, path); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	dirReady := db.EnsureSessionsDir(s.cfg.SessionDir) == nil
	tools := adapters.All()
	writeJSON(w, map[string]any{
		"status":             "ok",
		"time":               time.Now().UTC().Format(time.RFC3339),
		"sessions_dir":       s.cfg.SessionDir,
		"db_dir_ready":       dirReady,
		"auth_enabled":       s.cfg.APIKey != "",
		"llm_configured":     os.Getenv("NYX_LLM_BASE_URL") != "",
		"registered_tools":   len(tools),
		"session_dir_status": readiness(dirReady),
	})
}

func (s *Server) effectiveConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.AppConfig
	if cfg.Database.SessionDir == "" {
		cfg = appconfig.Default()
		cfg.Database.SessionDir = s.cfg.SessionDir
		cfg.Server.APIKey = s.cfg.APIKey
		cfg.Tools = s.cfg.ToolPaths
	}
	writeJSON(w, map[string]any{
		"database": map[string]any{"session_dir": firstNonEmpty(cfg.Database.SessionDir, s.cfg.SessionDir)},
		"server": map[string]any{
			"host":           cfg.Server.Host,
			"port":           cfg.Server.Port,
			"auth_enabled":   firstNonEmpty(cfg.Server.APIKey, s.cfg.APIKey) != "",
			"secure_cookies": cfg.Server.SecureCookies,
		},
		"llm": map[string]any{
			"enabled":     cfg.LLM.Enabled,
			"configured":  cfg.LLM.BaseURL != "",
			"provider":    cfg.LLM.Provider,
			"base_url":    cfg.LLM.BaseURL,
			"model":       cfg.LLM.Model,
			"api_key_set": cfg.LLM.APIKey != "",
			"max_tokens":  cfg.LLM.MaxTokens,
			"temperature": cfg.LLM.Temperature,
		},
		"scan": cfg.Scan,
		"cve": map[string]any{
			"offline_path":   cfg.CVE.OfflinePath,
			"enable_remote":  cfg.CVE.EnableRemote,
			"cache_ttl":      cfg.CVE.CacheTTL,
			"exploitdb_path": cfg.CVE.ExploitDBPath,
			"sources":        cfg.CVE.Sources,
		},
		"power":   cfg.Power.Redacted(),
		"tools":   cfg.Tools,
		"plugins": cfg.Plugins,
		"paths": map[string]string{
			"state_dir":         s.stateDir(),
			"scan_profiles":     s.scanProfilesPath(),
			"plugin_registry":   s.globalPluginsPath(),
			"plugin_bin_dir":    s.pluginBinDir(),
			"session_events_ws": "/api/scan/{id}/events",
		},
		"runtime": map[string]string{"goos": runtime.GOOS, "goarch": runtime.GOARCH},
	})
}

func absolutePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return filepath.Clean(value)
	}
	return abs
}

func splitEnvList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func envBool(name string) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err == nil {
		return parsed
	}
	switch strings.ToLower(value) {
	case "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func parseBoolQuery(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "valid":
		return true
	default:
		return false
	}
}

func (s *Server) generatePayloads(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ForceRegenerate bool `json:"force_regenerate"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	payloads, err := payload.Generate(r.Context(), store, r.PathValue("id"), r.PathValue("finding_id"), payload.GenerateOptions{
		Force:     req.ForceRegenerate,
		LLMConfig: llmintel.ConfigFromSession(session),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, payloads)
}

func (s *Server) listFindingPayloads(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	payloads, err := store.ListPayloadsByFinding(r.Context(), r.PathValue("id"), r.PathValue("finding_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, payloads)
}

func (s *Server) listSessionPayloads(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	filter := db.PayloadFilter{Type: strings.TrimSpace(r.URL.Query().Get("type"))}
	if value := strings.TrimSpace(r.URL.Query().Get("validated")); value != "" {
		parsed := parseBoolQuery(value)
		filter.Validated = &parsed
	}
	payloads, err := store.ListPayloadsBySession(r.Context(), r.PathValue("id"), filter)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, payloads)
}

func (s *Server) validatePayload(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "payload validation requires API key authentication") {
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	result, err := payload.Validate(r.Context(), store, session, r.PathValue("payload_id"), payload.ValidationOptions{
		Confirm: req.Confirm,
		Enabled: s.cfg.AppConfig.Power.ActiveValidation.Enabled,
		Client:  s.cfg.HTTPClient,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, result)
}

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	filter := db.CredentialFilter{Type: r.URL.Query().Get("type"), Service: r.URL.Query().Get("service")}
	if value := r.URL.Query().Get("valid"); strings.TrimSpace(value) != "" {
		parsed := parseBoolQuery(value)
		filter.Valid = &parsed
	}
	credentials, err := store.ListCredentialFindings(r.Context(), r.PathValue("id"), filter)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, creds.RedactAll(credentials, false))
}

func (s *Server) getCredential(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	credential, err := store.CredentialFindingByID(r.Context(), r.PathValue("id"), r.PathValue("credential_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, credential.Redacted())
}

func (s *Server) testCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "credential testing requires API key authentication") {
		return
	}
	var req creds.TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	req.MaxAttempts = firstPositive(req.MaxAttempts, s.cfg.AppConfig.Power.Credentials.MaxAttemptsPerUser)
	if req.DelayMS == 0 && s.cfg.AppConfig.Power.Credentials.DelaySeconds > 0 {
		req.DelayMS = s.cfg.AppConfig.Power.Credentials.DelaySeconds * 1000
	}
	req.StoreSecret = req.StoreSecret && s.cfg.AppConfig.Power.Credentials.StorePlaintext
	req.Client = s.cfg.HTTPClient
	credentials, err := creds.Run(r.Context(), store, r.PathValue("id"), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, creds.RedactAll(credentials, false))
}

func (s *Server) redactCredential(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "credential redaction requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	credential, err := store.CredentialFindingByID(r.Context(), r.PathValue("id"), r.PathValue("credential_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	credential.Password = ""
	if err := store.UpdateCredentialFinding(r.Context(), credential); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, credential)
}

func (s *Server) listOSINTFindings(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findings, err := store.ListOSINTFindings(r.Context(), r.PathValue("id"), db.OSINTFilter{Kind: r.URL.Query().Get("kind"), Source: r.URL.Query().Get("source")})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, findings)
}

func (s *Server) runOSINT(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "OSINT collection requires API key authentication") {
		return
	}
	var req osint.RunRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findings, err := osint.RunWithConfig(r.Context(), store, session, req, s.cfg.AppConfig.Power, s.cfg.HTTPClient)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, findings)
}

func (s *Server) seedOSINTFinding(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "OSINT seeding requires API key authentication") {
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	finding, err := store.OSINTFindingByID(r.Context(), r.PathValue("id"), r.PathValue("finding_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	if !req.Confirm {
		writeJSON(w, map[string]any{"seeded": false, "finding": finding, "reason": "operator confirmation required before adding scan targets"})
		return
	}
	if !osintFindingInScope(finding, session) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("OSINT finding is outside session scope"))
		return
	}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: finding.Value, Port: 443, Protocol: "https", IsAlive: false, DiscoveredBy: "osint/" + finding.Source, CreatedAt: time.Now().UTC()}
	if err := store.InsertTarget(r.Context(), target); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]any{"seeded": true, "target": target})
}

func (s *Server) listADEntities(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	entities, err := store.ListADEntities(r.Context(), r.PathValue("id"), r.URL.Query().Get("type"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, entities)
}

func (s *Server) listADRelationships(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	relationships, err := store.ListADRelationships(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, relationships)
}

func (s *Server) listADArtifacts(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	artifacts, err := store.ListADArtifacts(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, artifacts)
}

func (s *Server) runADEnum(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "AD enumeration requires API key authentication") {
		return
	}
	var req struct {
		Domain      string `json:"domain"`
		AllowPublic bool   `json:"allow_public"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	entities, err := activedirectory.RecordEnumRequest(r.Context(), store, session, req.Domain, req.AllowPublic)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	_, _ = activedirectory.RecordRelayRisks(r.Context(), store, session)
	writeJSON(w, entities)
}

func (s *Server) runADKerberoast(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "Kerberoast requests require API key authentication") {
		return
	}
	var req struct {
		Confirm     bool   `json:"confirm"`
		Domain      string `json:"domain"`
		Username    string `json:"username"`
		AllowPublic bool   `json:"allow_public"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	artifact, err := activedirectory.RecordKerberoastRequest(r.Context(), store, session, activedirectory.KerberoastRequest{Confirm: req.Confirm, Domain: req.Domain, Username: req.Username, AllowPublic: req.AllowPublic})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"started": false, "artifact": artifact, "reason": "Kerberoast request recorded; hash extraction and cracking are not automatic"})
}

func (s *Server) importBloodHound(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "BloodHound import requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	raw, ok := readLimitedBody(w, r, maxBloodHoundImportBytes)
	if !ok {
		return
	}
	if err := activedirectory.ImportBloodHound(r.Context(), store, r.PathValue("id"), raw); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"imported": true})
}

func (s *Server) exportBloodHound(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	entities, _ := store.ListADEntities(r.Context(), r.PathValue("id"), "")
	relationships, _ := store.ListADRelationships(r.Context(), r.PathValue("id"))
	writeJSON(w, map[string]any{"entities": entities, "relationships": relationships})
}

func (s *Server) listBlockEvents(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	events, err := store.ListBlockEvents(r.Context(), r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, events)
}

func (s *Server) listProviderStatuses(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	statuses, err := store.ListProviderStatuses(r.Context(), r.PathValue("id"), db.ProviderStatusFilter{
		Provider: r.URL.Query().Get("provider"),
		Module:   r.URL.Query().Get("module"),
		Status:   r.URL.Query().Get("status"),
	})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, statuses)
}

func (s *Server) listPowerCallbacks(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	filter := db.PowerCallbackFilter{FindingID: r.URL.Query().Get("finding_id"), Provider: r.URL.Query().Get("provider")}
	if value := r.URL.Query().Get("received"); strings.TrimSpace(value) != "" {
		parsed := parseBoolQuery(value)
		filter.Received = &parsed
	}
	callbacks, err := store.ListPowerCallbacks(r.Context(), r.PathValue("id"), filter)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, callbacks)
}

func (s *Server) recordPowerCallback(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "callback recording requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err := store.MarkPowerCallbackReceived(r.Context(), r.PathValue("id"), r.PathValue("token"), hostOnly(r.RemoteAddr), string(raw)); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"received": true})
}

func (s *Server) runPoC(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "PoC execution requires API key authentication") {
		return
	}
	var req poc.RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	req.ActiveValidationEnabled = s.cfg.AppConfig.Power.ActiveValidation.Enabled
	req.Client = s.cfg.HTTPClient
	if req.CallbackBaseURL == "" && s.cfg.AppConfig.Power.Callbacks.Provider == "builtin" {
		req.CallbackBaseURL = fmt.Sprintf("http://%s:%d/api/sessions/%s/callbacks", firstNonEmpty(s.cfg.Host, "127.0.0.1"), s.cfg.Port, r.PathValue("id"))
	}
	result, err := poc.Run(r.Context(), store, r.PathValue("id"), r.PathValue("finding_id"), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, result)
}

func (s *Server) listFindingPoCResults(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	results, err := store.ListPoCResults(r.Context(), r.PathValue("id"), r.PathValue("finding_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, results)
}

func (s *Server) listPoCResults(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	results, err := store.ListPoCResults(r.Context(), r.PathValue("id"), "")
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, results)
}

func (s *Server) importBurpXML(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "Burp import requires API key authentication") {
		return
	}
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	raw, ok := readLimitedBody(w, r, maxBurpImportBytes)
	if !ok {
		return
	}
	result, err := burp.ImportXML(r.Context(), store, session, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, result)
}

func (s *Server) exportBurpScope(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	raw, err := burp.ExportScope(r.Context(), store, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(raw) // #nosec G705 -- XML is generated by Nyx from stored scope records, not rendered as HTML.
}

func (s *Server) exportBurpFindings(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	raw, err := burp.ExportFindings(r.Context(), store, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(raw) // #nosec G705 -- XML is generated by Nyx from stored findings export records, not rendered as HTML.
}

func (s *Server) pushBurpScope(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "Burp REST actions require API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	config, err := s.currentBurpConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result, err := burp.PushScope(r.Context(), store, r.PathValue("id"), config, s.cfg.HTTPClient)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, result)
}

func (s *Server) pullBurpIssues(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "Burp REST actions require API key authentication") {
		return
	}
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	config, err := s.currentBurpConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	imported, result, err := burp.PullIssues(r.Context(), store, session, config, s.cfg.HTTPClient)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]any{"result": result, "imported": imported})
}

func (s *Server) burpStatus(w http.ResponseWriter, r *http.Request) {
	config, err := s.currentBurpConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result := burp.Status(r.Context(), config, s.cfg.HTTPClient)
	writeJSON(w, map[string]any{"configured": config.BaseURL != "" || config.CollaboratorProvider != "", "available": result.Available, "config": config.Redacted(), "result": result})
}

func (s *Server) currentBurpConfig(ctx context.Context) (models.BurpConfig, error) {
	store, err := s.openState(ctx)
	if err != nil {
		return models.BurpConfig{}, err
	}
	defer store.Close()
	config, err := store.GetBurpConfig(ctx)
	if err == nil {
		return config, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return models.BurpConfig{}, err
	}
	now := time.Now().UTC()
	return models.BurpConfig{
		ID:                   "config",
		BaseURL:              s.cfg.AppConfig.Power.Burp.BaseURL,
		APIKey:               s.cfg.AppConfig.Power.Burp.APIKey,
		CollaboratorProvider: s.cfg.AppConfig.Power.Callbacks.Provider,
		CollaboratorURL:      s.cfg.AppConfig.Power.Callbacks.InteractshURL,
		CreatedAt:            now,
		UpdatedAt:            now,
	}, nil
}

func (s *Server) setupBurpCollaborator(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "Burp collaborator setup requires API key authentication") {
		return
	}
	var config models.BurpConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	if config.ID == "" {
		config.ID = models.NewID()
	}
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	if err := store.UpsertBurpConfig(r.Context(), config); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, config.Redacted())
}

func (s *Server) listBurpCallbacks(w http.ResponseWriter, r *http.Request) {
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	callbacks, err := store.ListBurpCallbacks(r.Context(), r.URL.Query().Get("session_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, callbacks)
}

type startScanRequest struct {
	Target                    string                    `json:"target"`
	Targets                   []string                  `json:"targets"`
	SourcePath                string                    `json:"source_path"`
	Name                      string                    `json:"name"`
	Mode                      models.ScanMode           `json:"mode"`
	OutOfScope                []string                  `json:"out_of_scope"`
	EnabledPhases             []string                  `json:"enabled_phases"`
	Tools                     []string                  `json:"tools"`
	ToolParameters            map[string]map[string]any `json:"tool_parameters"`
	Concurrency               int                       `json:"concurrency"`
	PerToolConcurrency        int                       `json:"per_tool_concurrency"`
	ToolTimeoutSeconds        int                       `json:"tool_timeout_seconds"`
	ToolDelayMS               int                       `json:"tool_delay_ms"`
	RateLimit                 string                    `json:"rate_limit"`
	RouteSeeds                []string                  `json:"route_seeds"`
	AuthHeaders               map[string]string         `json:"auth_headers"`
	AuthCookies               map[string]string         `json:"auth_cookies"`
	AuthCookieHeader          string                    `json:"auth_cookie_header"`
	AuthProfile               map[string]any            `json:"auth_profile"`
	SecondaryAuthHeaders      map[string]string         `json:"secondary_auth_headers"`
	SecondaryAuthCookies      map[string]string         `json:"secondary_auth_cookies"`
	SecondaryAuthCookieHeader string                    `json:"secondary_auth_cookie_header"`
	EvasionProfile            string                    `json:"evasion_profile"`
	JitterMS                  int                       `json:"jitter_ms"`
	ProxyURL                  string                    `json:"proxy_url"`
	UserAgentProfile          string                    `json:"user_agent_profile"`
	HeaderProfile             string                    `json:"header_profile"`
	AdaptiveBackoff           bool                      `json:"adaptive_backoff"`
	MaxBackoffSeconds         int                       `json:"max_backoff_seconds"`
	LLMModel                  string                    `json:"llm_model"`
	LLMBaseURL                string                    `json:"llm_base_url"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.SourcePath = strings.TrimSpace(req.SourcePath)
	if len(req.Targets) > 0 {
		req.Target = strings.Join(req.Targets, "\n")
	}
	if requiresPrivilegedScan(req, len(s.enabledGlobalPlugins()) > 0) && !s.requireConfiguredAPIKey(w, "privileged scan options require API key authentication") {
		return
	}
	if req.SourcePath != "" {
		sourcePath, err := s.canonicalSourcePath(req.SourcePath)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.SourcePath = sourcePath
	}
	if err := validateTools(req.Tools); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := adapters.ValidateToolParameters(req.ToolParameters); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.LLMBaseURL) != "" {
		if err := llmintel.ValidateBaseURL(req.LLMBaseURL, s.cfg.LLMAllowedHosts); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	runnerOptions, _, err := evasion.Normalize(models.ScanRunnerOptions{
		Concurrency:        req.Concurrency,
		PerToolConcurrency: req.PerToolConcurrency,
		ToolTimeoutSeconds: req.ToolTimeoutSeconds,
		ToolDelayMS:        req.ToolDelayMS,
		RateLimit:          req.RateLimit,
		EvasionProfile:     req.EvasionProfile,
		JitterMS:           req.JitterMS,
		ProxyURL:           req.ProxyURL,
		UserAgentProfile:   req.UserAgentProfile,
		HeaderProfile:      req.HeaderProfile,
		AdaptiveBackoff:    req.AdaptiveBackoff,
		MaxBackoffSeconds:  req.MaxBackoffSeconds,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	input := engine.NewSessionInput{
		Target:         req.Target,
		SourcePath:     req.SourcePath,
		Name:           req.Name,
		Mode:           req.Mode,
		OutOfScope:     req.OutOfScope,
		EnabledPhases:  req.EnabledPhases,
		EnabledTools:   req.Tools,
		ToolParameters: models.BuildScanToolParameters(req.ToolParameters, req.RouteSeeds, "", req.AuthHeaders, req.AuthCookies, req.AuthCookieHeader, req.AuthProfile, req.SecondaryAuthHeaders, req.SecondaryAuthCookies, req.SecondaryAuthCookieHeader),
		RunnerOptions:  runnerOptions,
		LLMModel:       req.LLMModel,
		LLMBaseURL:     req.LLMBaseURL,
	}
	var session models.Session
	var targets []models.Target
	var sessionErr error
	if req.Target == "" && req.SourcePath != "" {
		session, sessionErr = engine.NewPendingSourceSession(input)
	} else {
		if req.SourcePath != "" {
			input.WorkloadMode = models.WorkloadModeCombined
		}
		session, targets, sessionErr = engine.NewPendingSessionWithTargets(input)
	}
	if sessionErr != nil {
		writeError(w, http.StatusBadRequest, sessionErr)
		return
	}
	record, err := db.CreateSessionDBWithTargets(r.Context(), s.cfg.SessionDir, session, targets)
	if err != nil {
		writeDBError(w, err)
		return
	}
	s.scanManager.Start(record.Session)
	writeJSONStatus(w, http.StatusAccepted, record)
}

type sourceRootResponse struct {
	Roots []sourceRootRecord `json:"roots"`
}

type sourceRootRecord struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

type sourceDirResponse struct {
	Path        string            `json:"path"`
	ParentPath  string            `json:"parent_path,omitempty"`
	Directories []sourceDirRecord `json:"directories"`
}

type sourceDirRecord struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func (s *Server) sourceRoots(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, sourceRootResponse{Roots: s.availableSourceRoots()})
}

func (s *Server) sourceDirs(w http.ResponseWriter, r *http.Request) {
	requested := strings.TrimSpace(r.URL.Query().Get("path"))
	if requested == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("path is required"))
		return
	}
	resolved, root, err := s.resolveBrowsableSourceDir(requested)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("source directory is not accessible: %w", err))
		return
	}
	directories := make([]sourceDirRecord, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childPath := filepath.Join(resolved, entry.Name())
		childResolved, err := filepath.EvalSymlinks(childPath)
		if err != nil {
			continue
		}
		if !pathInsideOrEqual(root.Path, childResolved) {
			continue
		}
		directories = append(directories, sourceDirRecord{Name: entry.Name(), Path: filepath.Clean(childResolved)})
	}
	parentPath := ""
	parent := filepath.Dir(resolved)
	if parent != resolved && pathInsideOrEqual(root.Path, parent) {
		parentPath = filepath.Clean(parent)
	}
	writeJSON(w, sourceDirResponse{Path: filepath.Clean(resolved), ParentPath: parentPath, Directories: directories})
}

func (s *Server) availableSourceRoots() []sourceRootRecord {
	candidates := s.cfg.SourceRoots
	if len(candidates) == 0 {
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, home)
		}
		if cwd, err := os.Getwd(); err == nil {
			candidates = append(candidates, cwd)
		}
	}
	seen := make(map[string]bool)
	roots := make([]sourceRootRecord, 0, len(candidates))
	for _, candidate := range candidates {
		resolved, ok := canonicalExistingDir(candidate)
		if !ok || seen[resolved] {
			continue
		}
		seen[resolved] = true
		roots = append(roots, sourceRootRecord{Path: resolved, Label: sourceRootLabel(resolved)})
	}
	return roots
}

func (s *Server) resolveBrowsableSourceDir(value string) (string, sourceRootRecord, error) {
	resolved, ok := canonicalExistingDir(value)
	if !ok {
		return "", sourceRootRecord{}, fmt.Errorf("source directory is not accessible")
	}
	for _, root := range s.availableSourceRoots() {
		if pathInsideOrEqual(root.Path, resolved) {
			return resolved, root, nil
		}
	}
	return "", sourceRootRecord{}, fmt.Errorf("source directory is outside the configured roots")
}

func canonicalExistingDir(value string) (string, bool) {
	path := strings.TrimSpace(value)
	if path == "" {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved) // #nosec G703 -- resolved is produced by EvalSymlinks and constrained to source roots before directory contents are exposed.
	if err != nil || !info.IsDir() {
		return "", false
	}
	return filepath.Clean(resolved), true
}

func sourceRootLabel(path string) string {
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == path {
		return "Home"
	}
	if cwd, err := os.Getwd(); err == nil {
		if resolved, ok := canonicalExistingDir(cwd); ok && resolved == path {
			return "Workspace"
		}
	}
	return filepath.Base(path)
}

func requiresPrivilegedScan(req startScanRequest, enabledGlobalPlugins bool) bool {
	if strings.TrimSpace(req.SourcePath) != "" {
		return true
	}
	if len(req.AuthHeaders) > 0 || len(req.AuthCookies) > 0 || strings.TrimSpace(req.AuthCookieHeader) != "" {
		return true
	}
	if len(req.SecondaryAuthHeaders) > 0 || len(req.SecondaryAuthCookies) > 0 || strings.TrimSpace(req.SecondaryAuthCookieHeader) != "" {
		return true
	}
	if len(req.AuthProfile) > 0 {
		return true
	}
	for _, tool := range req.Tools {
		if strings.HasPrefix(strings.TrimSpace(tool), "plugin:") {
			return true
		}
	}
	return enabledGlobalPlugins && len(req.Tools) == 0
}

func (s *Server) canonicalSourcePath(value string) (string, error) {
	path := strings.TrimSpace(value)
	if path == "" {
		return "", nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("source_path is not accessible: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("source_path is not accessible: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("source_path must be a directory")
	}
	resolved = filepath.Clean(resolved)
	if len(s.cfg.SourceRoots) > 0 && !sourcePathAllowed(resolved, s.cfg.SourceRoots) {
		return "", fmt.Errorf("source_path is outside the configured allowlist")
	}
	return resolved, nil
}

func sourcePathAllowed(path string, roots []string) bool {
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if pathInsideOrEqual(filepath.Clean(resolved), path) {
			return true
		}
	}
	return false
}

func pathInsideOrEqual(root, candidate string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}

func readiness(ok bool) string {
	if ok {
		return "ready"
	}
	return "unavailable"
}

func parseQueryBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func hostOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func osintFindingInScope(finding models.OSINTFinding, session models.Session) bool {
	value := strings.ToLower(strings.TrimSpace(finding.Value))
	if value == "" {
		return false
	}
	for _, scope := range append([]string{session.TargetInput}, session.InScope...) {
		host := strings.ToLower(scopeHost(scope))
		if host == value || strings.HasSuffix(value, "."+host) {
			return true
		}
	}
	return false
}

func scopeHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	raw, _, _ = strings.Cut(raw, "/")
	raw, _, _ = strings.Cut(raw, ":")
	return raw
}

func (s *Server) scanStatus(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"id":            session.ID,
		"status":        session.Status,
		"target_count":  session.TargetCount,
		"finding_count": session.FindingCount,
		"started_at":    session.StartedAt,
		"completed_at":  session.CompletedAt,
	})
}

func (s *Server) stopScan(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, sessionID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	if !s.scanManager.Stop(session.ID) {
		writeError(w, http.StatusConflict, fmt.Errorf("scan %s is not running", session.ID))
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"id":     session.ID,
		"status": models.SessionStatusCancelled,
	})
}

func (s *Server) pauseScan(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if !s.scanManager.Pause(sessionID) {
		writeError(w, http.StatusConflict, fmt.Errorf("scan %s is not running", sessionID))
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"id": sessionID, "status": "paused"})
}

func (s *Server) resumeScan(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if !s.scanManager.Resume(sessionID) {
		writeError(w, http.StatusConflict, fmt.Errorf("scan %s is not running", sessionID))
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"id": sessionID, "status": models.SessionStatusRunning})
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

func writeDBError(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		writeRequestBodyError(w, err)
		return nil, false
	}
	return body, true
}

func writeRequestBodyError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", maxErr.Limit))
		return
	}
	writeError(w, http.StatusBadRequest, err)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
