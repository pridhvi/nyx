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
	"os/exec"
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
	"github.com/pridhvi/nyx/internal/report"
	"github.com/pridhvi/nyx/internal/state"
)

type Config struct {
	Host            string
	Port            int
	SessionDir      string
	APIKey          string
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
	authFailures map[string][]time.Time
	authSessions map[string]time.Time
}

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
	cfg.AppConfig.Server.APIKey = cfg.APIKey
	cfg.SourceRoots = append(cfg.SourceRoots, splitEnvList(os.Getenv("NYX_SOURCE_ROOTS"))...)
	cfg.LLMAllowedHosts = append(cfg.LLMAllowedHosts, splitEnvList(os.Getenv("NYX_LLM_ALLOWED_HOSTS"))...)
	server := &Server{
		cfg:          cfg,
		scanManager:  NewScanManager(cfg.SessionDir, cfg.HTTPClient),
		authFailures: make(map[string][]time.Time),
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
	defer func() {
		scheduler.Stop()
		s.monitorMu.Lock()
		s.monitorSched = nil
		s.monitorMu.Unlock()
	}()
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("nyx api listening", "address", server.Addr)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
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
	return s.withAuth(mux)
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
			"host":         cfg.Server.Host,
			"port":         cfg.Server.Port,
			"auth_enabled": firstNonEmpty(cfg.Server.APIKey, s.cfg.APIKey) != "",
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

type authLoginRequest struct {
	APIKey string `json:"api_key"`
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) == "" {
		writeJSON(w, map[string]any{"authenticated": true, "auth_enabled": false})
		return
	}
	client := clientKey(r)
	if s.authLimited(client) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
		return
	}
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.recordAuthFailure(client)
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid login request"))
		return
	}
	if req.APIKey != s.cfg.APIKey {
		s.recordAuthFailure(client)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid API key"))
		return
	}
	token, expires := s.createAuthSession()
	http.SetCookie(w, authSessionCookie(token, expires, r.TLS != nil))
	writeJSON(w, map[string]any{"authenticated": true, "auth_enabled": true, "expires_at": expires.UTC().Format(time.RFC3339)})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(authSessionCookieName); err == nil {
		s.deleteAuthSession(cookie.Value)
	}
	http.SetCookie(w, expiredAuthSessionCookie(r.TLS != nil))
	writeJSON(w, map[string]any{"authenticated": false})
}

type toolParameter struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Default     any      `json:"default,omitempty"`
	Options     []string `json:"options,omitempty"`
	Description string   `json:"description,omitempty"`
}

type toolRecord struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	HomepageURL    string          `json:"homepage_url"`
	Phase          string          `json:"phase"`
	DependsOn      []string        `json:"depends_on"`
	Kind           string          `json:"kind"`
	DefaultEnabled bool            `json:"default_enabled"`
	Installed      bool            `json:"installed"`
	BinaryPath     string          `json:"binary_path"`
	Version        string          `json:"version"`
	InstallHint    string          `json:"install_hint"`
	Parameters     []toolParameter `json:"parameters"`
	LastRun        *models.ToolRun `json:"last_run,omitempty"`
}

func (s *Server) tools(w http.ResponseWriter, r *http.Request) {
	registered := adapters.All()
	lastRuns := map[string]models.ToolRun{}
	if sessionID := strings.TrimSpace(r.URL.Query().Get("session_id")); sessionID != "" {
		if store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, sessionID); err == nil {
			if session, err := store.GetSession(r.Context()); err == nil {
				if runs, err := store.ListToolRuns(r.Context(), session.ID); err == nil {
					for _, run := range runs {
						lastRuns[run.ToolID] = run
					}
				}
			}
			_ = store.Close()
		}
	}
	tools := make([]toolRecord, 0, len(registered))
	for _, adapter := range registered {
		record := s.toolRecord(adapter)
		if run, ok := lastRuns[adapter.ID()]; ok {
			record.LastRun = &run
		}
		tools = append(tools, record)
	}
	for _, plugin := range s.enabledGlobalPlugins() {
		record := s.toolRecord(adapters.NewConfiguredPlugin(plugin))
		record.Kind = "plugin"
		record.Installed = validatePluginBinary(plugin.Binary) == nil
		record.BinaryPath = plugin.Binary
		record.Description = plugin.Description
		record.HomepageURL = plugin.HomepageURL
		record.InstallHint = firstNonEmpty(plugin.Description, "Global plugin.")
		tools = append(tools, record)
	}
	writeJSON(w, tools)
}

func (s *Server) toolRecord(adapter adapters.Adapter) toolRecord {
	id := adapter.ID()
	deps := adapter.DependsOn()
	if deps == nil {
		deps = []string{}
	}
	binary := binaryNameForTool(id)
	parameters := parametersForTool(id)
	if parameters == nil {
		parameters = []toolParameter{}
	}
	path := ""
	installed := true
	version := ""
	kind := "builtin_http"
	if binary != "" {
		kind = "subprocess"
		path, installed = s.detectToolBinary(id, binary)
		if installed {
			version = detectVersion(path)
		}
	}
	return toolRecord{
		ID:             id,
		Name:           adapter.Name(),
		Description:    descriptionForTool(id),
		HomepageURL:    homepageForTool(id),
		Phase:          string(adapter.Phase()),
		DependsOn:      deps,
		Kind:           kind,
		DefaultEnabled: id != "crtsh",
		Installed:      installed,
		BinaryPath:     path,
		Version:        version,
		InstallHint:    installHintForTool(id, binary),
		Parameters:     parameters,
	}
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

func parseBoolQuery(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "valid":
		return true
	default:
		return false
	}
}

func (s *Server) stateDir() string {
	if filepath.Base(s.cfg.SessionDir) == "sessions" {
		return filepath.Dir(s.cfg.SessionDir)
	}
	return s.cfg.SessionDir
}

func (s *Server) stateDBPath() string {
	return state.DBPath(s.stateDir())
}

func (s *Server) openState(ctx context.Context) (*state.Store, error) {
	return state.Open(ctx, s.stateDBPath())
}

func (s *Server) reloadMonitorScheduler(ctx context.Context) {
	s.monitorMu.Lock()
	scheduler := s.monitorSched
	s.monitorMu.Unlock()
	if scheduler != nil {
		if err := scheduler.Reload(ctx); err != nil {
			slog.Warn("reload monitor scheduler", "error", err)
		}
	}
}

func (s *Server) detectToolBinary(toolID, binary string) (string, bool) {
	for _, candidate := range []string{s.cfg.ToolPaths[toolID], s.cfg.ToolPaths[binary]} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	path, err := exec.LookPath(binary)
	return path, err == nil
}

type scanProfileRecord struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Request     startScanRequest `json:"request"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type scanProfileRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Request     startScanRequest `json:"request"`
}

type monitorConfigRequest struct {
	Name               string                           `json:"name"`
	TargetInput        string                           `json:"target_input"`
	InScope            []string                         `json:"in_scope"`
	OutOfScope         []string                         `json:"out_of_scope"`
	Schedule           string                           `json:"schedule"`
	EnabledPhases      []string                         `json:"enabled_phases"`
	EnabledTools       []string                         `json:"enabled_tools"`
	ToolParameters     map[string]map[string]any        `json:"tool_parameters"`
	RunnerOptions      models.ScanRunnerOptions         `json:"runner_options"`
	AlertOn            []string                         `json:"alert_on"`
	NotificationConfig models.MonitorNotificationConfig `json:"notification_config"`
	BaselineSessionID  string                           `json:"baseline_session_id"`
	Enabled            *bool                            `json:"enabled"`
}

func (s *Server) listMonitorConfigs(w http.ResponseWriter, r *http.Request) {
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	configs, err := store.ListMonitorConfigs(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, monitor.RedactConfigs(configs))
}

func (s *Server) getMonitorConfig(w http.ResponseWriter, r *http.Request) {
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	config, err := store.GetMonitorConfig(r.Context(), r.PathValue("config_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, config.Redacted())
}

func (s *Server) createMonitorConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "monitor configuration requires API key authentication") {
		return
	}
	var req monitorConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	config, err := monitorConfigFromRequest(req, models.NewID(), time.Time{})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	config, err = monitor.NormalizeConfig(config, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	if err := store.UpsertMonitorConfig(r.Context(), config); err != nil {
		writeDBError(w, err)
		return
	}
	s.reloadMonitorScheduler(r.Context())
	writeJSONStatus(w, http.StatusCreated, config.Redacted())
}

func (s *Server) updateMonitorConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "monitor configuration requires API key authentication") {
		return
	}
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	existing, err := store.GetMonitorConfig(r.Context(), r.PathValue("config_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	var req monitorConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	config, err := monitorConfigFromRequest(req, existing.ID, existing.CreatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if config.NotificationConfig.SlackWebhookURL == "" || config.NotificationConfig.SlackWebhookURL == "********" {
		config.NotificationConfig.SlackWebhookURL = existing.NotificationConfig.SlackWebhookURL
	}
	if config.NotificationConfig.DiscordWebhookURL == "" || config.NotificationConfig.DiscordWebhookURL == "********" {
		config.NotificationConfig.DiscordWebhookURL = existing.NotificationConfig.DiscordWebhookURL
	}
	if config.BaselineSessionID == "" {
		config.BaselineSessionID = existing.BaselineSessionID
	}
	if config.LastRunAt == nil {
		config.LastRunAt = existing.LastRunAt
	}
	if req.Enabled == nil {
		config.Enabled = existing.Enabled
	}
	config, err = monitor.NormalizeConfig(config, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := store.UpsertMonitorConfig(r.Context(), config); err != nil {
		writeDBError(w, err)
		return
	}
	s.reloadMonitorScheduler(r.Context())
	writeJSON(w, config.Redacted())
}

func (s *Server) deleteMonitorConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "monitor configuration requires API key authentication") {
		return
	}
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	if err := store.DeleteMonitorConfig(r.Context(), r.PathValue("config_id")); err != nil {
		writeDBError(w, err)
		return
	}
	s.reloadMonitorScheduler(r.Context())
	writeJSON(w, map[string]bool{"deleted": true})
}

func (s *Server) runMonitorConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "monitor runs require API key authentication") {
		return
	}
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	runner := monitor.Runner{State: store, SessionDir: s.cfg.SessionDir, HTTPClient: s.cfg.HTTPClient}
	run, changes, err := runner.RunNow(r.Context(), r.PathValue("config_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	config, err := store.GetMonitorConfig(r.Context(), r.PathValue("config_id"))
	if err == nil {
		_ = monitor.Alert(r.Context(), store, config, changes)
	}
	s.reloadMonitorScheduler(r.Context())
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"run": run, "changes": changes})
}

func (s *Server) listMonitorRuns(w http.ResponseWriter, r *http.Request) {
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	runs, err := store.ListMonitorRuns(r.Context(), state.MonitorRunFilter{ConfigID: strings.TrimSpace(r.URL.Query().Get("config_id"))})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, runs)
}

func (s *Server) listMonitorRunChanges(w http.ResponseWriter, r *http.Request) {
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	run, err := store.GetMonitorRun(r.Context(), r.PathValue("run_id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	changes, err := store.ListSurfaceChanges(r.Context(), run.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, changes)
}

func (s *Server) markMonitorChangeAlerted(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "monitor alert state requires API key authentication") {
		return
	}
	store, err := s.openState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer store.Close()
	if err := store.MarkSurfaceChangeAlerted(r.Context(), r.PathValue("change_id")); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"alerted": true})
}

func monitorConfigFromRequest(req monitorConfigRequest, id string, createdAt time.Time) (models.MonitorConfig, error) {
	if err := validateTools(req.EnabledTools); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := adapters.ValidateToolParameters(req.ToolParameters); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := monitor.ValidateAlertTriggers(req.AlertOn); err != nil {
		return models.MonitorConfig{}, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return models.MonitorConfig{
		ID:                 id,
		Name:               req.Name,
		TargetInput:        req.TargetInput,
		InScope:            req.InScope,
		OutOfScope:         req.OutOfScope,
		Schedule:           req.Schedule,
		EnabledPhases:      req.EnabledPhases,
		EnabledTools:       req.EnabledTools,
		ToolParameters:     req.ToolParameters,
		RunnerOptions:      req.RunnerOptions,
		AlertOn:            req.AlertOn,
		NotificationConfig: req.NotificationConfig,
		BaselineSessionID:  req.BaselineSessionID,
		Enabled:            enabled,
		CreatedAt:          createdAt,
	}, nil
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
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
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
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
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
	_, _ = w.Write(raw)
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
	_, _ = w.Write(raw)
}

func (s *Server) burpUnavailable(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireConfiguredAPIKey(w, "Burp REST actions require API key authentication") {
			return
		}
		writeJSON(w, map[string]any{"available": false, "action": action, "reason": "Burp REST client is not configured"})
	}
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

func (s *Server) listScanProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, profiles)
}

func (s *Server) createScanProfile(w http.ResponseWriter, r *http.Request) {
	var req scanProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("profile name is required"))
		return
	}
	if err := validateTools(req.Request.Tools); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := adapters.ValidateToolParameters(req.Request.ToolParameters); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Request = redactedScanProfileRequest(req.Request)
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	profile := scanProfileRecord{
		ID:          models.NewID(),
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		Request:     req.Request,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	profiles = append(profiles, profile)
	if err := s.writeScanProfiles(profiles); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, profile)
}

func redactedScanProfileRequest(req startScanRequest) startScanRequest {
	req.AuthHeaders = nil
	req.AuthCookies = nil
	req.AuthCookieHeader = ""
	req.AuthProfile = nil
	req.SecondaryAuthHeaders = nil
	req.SecondaryAuthCookies = nil
	req.SecondaryAuthCookieHeader = ""
	return req
}

func (s *Server) deleteScanProfile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("profile_id"))
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	next := profiles[:0]
	deleted := false
	for _, profile := range profiles {
		if profile.ID == id {
			deleted = true
			continue
		}
		next = append(next, profile)
	}
	if !deleted {
		writeDBError(w, db.ErrNotFound)
		return
	}
	if err := s.writeScanProfiles(next); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": id})
}

func (s *Server) scanProfilesPath() string {
	return filepath.Join(s.stateDir(), "scan-profiles.json")
}

func (s *Server) readScanProfiles() ([]scanProfileRecord, error) {
	path := s.scanProfilesPath()
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []scanProfileRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var profiles []scanProfileRecord
	if err := json.Unmarshal(body, &profiles); err != nil {
		return nil, err
	}
	if profiles == nil {
		profiles = []scanProfileRecord{}
	}
	return profiles, nil
}

func (s *Server) writeScanProfiles(profiles []scanProfileRecord) error {
	if err := os.MkdirAll(s.stateDir(), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.scanProfilesPath(), body, 0o600)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	records, err := db.ListSessions(r.Context(), s.cfg.SessionDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, records)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, session)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	_ = s.scanManager.Stop(sessionID)
	if err := db.DeleteSession(r.Context(), s.cfg.SessionDir, sessionID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": sessionID})
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
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
	targets, err := store.ListTargets(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, targets)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
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
	findings, err := store.ListFindings(r.Context(), session.ID, db.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		ToolID:   firstNonEmpty(r.URL.Query().Get("tool_id"), r.URL.Query().Get("tool")),
		Type:     r.URL.Query().Get("type"),
		Status:   r.URL.Query().Get("status"),
		Origin:   r.URL.Query().Get("origin"),
	})
	if err != nil {
		writeDBError(w, err)
		return
	}
	findings = filterFindings(findings, r.URL.Query().Get("cve"), r.URL.Query().Get("exploit"))
	if page, limit := pagination(r); limit > 0 {
		findings = paginate(findings, page, limit)
	}
	writeJSON(w, findings)
}

func (s *Server) listSourceFindings(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findings, err := store.ListSourceFindings(r.Context(), session.ID, db.SourceFindingFilter{Kind: r.URL.Query().Get("kind")})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, findings)
}

type updateFindingRequest struct {
	Severity    models.Severity `json:"severity"`
	Remediation string          `json:"remediation"`
}

func (s *Server) updateFinding(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findingID := r.PathValue("finding_id")
	var req updateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid severity %q", req.Severity))
		return
	}
	if err := store.UpdateFinding(r.Context(), findingID, req.Severity, req.Remediation); err != nil {
		writeDBError(w, err)
		return
	}
	findings, err := store.ListFindings(r.Context(), session.ID, db.FindingFilter{})
	if err != nil {
		writeDBError(w, err)
		return
	}
	for _, finding := range findings {
		if finding.ID == findingID {
			writeJSON(w, finding)
			return
		}
	}
	writeDBError(w, db.ErrNotFound)
}

func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	plugins, err := store.ListPlugins(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, plugins)
}

type pluginRequest struct {
	Name        string `json:"name"`
	Binary      string `json:"binary"`
	Phase       string `json:"phase"`
	Description string `json:"description"`
	HomepageURL string `json:"homepage_url"`
	Enabled     *bool  `json:"enabled"`
}

func (s *Server) globalPluginsPath() string {
	return filepath.Join(s.stateDir(), "plugins.json")
}

func (s *Server) pluginBinDir() string {
	return filepath.Join(s.stateDir(), "plugins", "bin")
}

func (s *Server) requireConfiguredAPIKey(w http.ResponseWriter, reason string) bool {
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": reason})
	return false
}

func (s *Server) listGlobalPlugins(w http.ResponseWriter, r *http.Request) {
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, plugins)
}

func (s *Server) createGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plugin, err := pluginFromRequest(req, models.NewID(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	plugins = append(plugins, plugin)
	if err := s.writeGlobalPlugins(plugins); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, plugin)
}

func (s *Server) updateGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("plugin_id"))
	for i := range plugins {
		if plugins[i].ID != id {
			continue
		}
		var req pluginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			plugins[i].Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Binary) != "" {
			if err := validatePluginBinary(req.Binary); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			plugins[i].Binary = strings.TrimSpace(req.Binary)
		}
		if strings.TrimSpace(req.Phase) != "" {
			if err := validatePluginPhase(req.Phase); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			plugins[i].Phase = strings.TrimSpace(req.Phase)
		}
		if req.Description != "" {
			plugins[i].Description = strings.TrimSpace(req.Description)
		}
		if req.HomepageURL != "" {
			plugins[i].HomepageURL = strings.TrimSpace(req.HomepageURL)
		}
		if req.Enabled != nil {
			plugins[i].Enabled = *req.Enabled
		}
		plugins[i].UpdatedAt = time.Now().UTC()
		if err := s.writeGlobalPlugins(plugins); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, plugins[i])
		return
	}
	writeDBError(w, db.ErrNotFound)
}

func (s *Server) deleteGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("plugin_id"))
	next := plugins[:0]
	deleted := false
	for _, plugin := range plugins {
		if plugin.ID == id {
			deleted = true
			continue
		}
		next = append(next, plugin)
	}
	if !deleted {
		writeDBError(w, db.ErrNotFound)
		return
	}
	if err := s.writeGlobalPlugins(next); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": id})
}

func (s *Server) uploadPluginBinary(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "plugin upload requires API key authentication") {
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	file, header, err := r.FormFile("binary")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	if err := os.MkdirAll(s.pluginBinDir(), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := safePluginFilename(header.Filename)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "plugin-" + models.NewID()
	}
	path := filepath.Join(s.pluginBinDir(), name)
	if _, err := os.Stat(path); err == nil {
		path = filepath.Join(s.pluginBinDir(), models.NewID()+"-"+name)
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"binary": path})
}

func safePluginFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Server) readGlobalPlugins() ([]models.PluginRecord, error) {
	body, err := os.ReadFile(s.globalPluginsPath())
	if errors.Is(err, os.ErrNotExist) {
		return []models.PluginRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var plugins []models.PluginRecord
	if err := json.Unmarshal(body, &plugins); err != nil {
		return nil, err
	}
	if plugins == nil {
		plugins = []models.PluginRecord{}
	}
	return plugins, nil
}

func (s *Server) writeGlobalPlugins(plugins []models.PluginRecord) error {
	if err := os.MkdirAll(s.stateDir(), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.globalPluginsPath(), body, 0o600)
}

func (s *Server) enabledGlobalPlugins() []models.PluginRecord {
	plugins, _ := s.readGlobalPlugins()
	var out []models.PluginRecord
	for _, plugin := range plugins {
		if plugin.Enabled {
			out = append(out, plugin)
		}
	}
	return out
}

func pluginFromRequest(req pluginRequest, id string, now time.Time) (models.PluginRecord, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return models.PluginRecord{}, fmt.Errorf("plugin name is required")
	}
	binary := strings.TrimSpace(req.Binary)
	if err := validatePluginBinary(binary); err != nil {
		return models.PluginRecord{}, err
	}
	phase := strings.TrimSpace(req.Phase)
	if phase == "" {
		phase = string(adapters.PhaseVulnScan)
	}
	if err := validatePluginPhase(phase); err != nil {
		return models.PluginRecord{}, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return models.PluginRecord{ID: id, Name: name, Binary: binary, Phase: phase, Description: strings.TrimSpace(req.Description), HomepageURL: strings.TrimSpace(req.HomepageURL), Enabled: enabled, CreatedAt: now, UpdatedAt: now}, nil
}

func validatePluginPhase(phase string) error {
	switch adapters.Phase(strings.TrimSpace(phase)) {
	case adapters.PhaseRecon, adapters.PhaseFingerprint, adapters.PhaseEnumerate, adapters.PhaseVulnScan:
		return nil
	default:
		return fmt.Errorf("unsupported plugin phase %q", phase)
	}
}

func (s *Server) upsertPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "session plugin management requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Binary = strings.TrimSpace(req.Binary)
	if req.Binary == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("binary is required"))
		return
	}
	if err := validatePluginBinary(req.Binary); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(req.Binary), filepath.Ext(req.Binary))
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now().UTC()
	plugin := models.PluginRecord{ID: models.NewID(), Name: name, Binary: req.Binary, Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	if err := store.UpsertPlugin(r.Context(), plugin); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, plugin)
}

func (s *Server) updatePlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "session plugin management requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	plugins, err := store.ListPlugins(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	var existing *models.PluginRecord
	for i := range plugins {
		if plugins[i].ID == r.PathValue("plugin_id") {
			existing = &plugins[i]
			break
		}
	}
	if existing == nil {
		writeDBError(w, db.ErrNotFound)
		return
	}
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Binary) != "" {
		binary := strings.TrimSpace(req.Binary)
		if err := validatePluginBinary(binary); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		existing.Binary = binary
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := store.UpsertPlugin(r.Context(), *existing); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, existing)
}

func validatePluginBinary(binary string) error {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return fmt.Errorf("binary is required")
	}
	if strings.ContainsAny(binary, "\x00\r\n") || strings.Contains(binary, " ") {
		return fmt.Errorf("plugin binary must be a single executable path or PATH-resolvable command")
	}
	if filepath.IsAbs(binary) || strings.Contains(binary, string(filepath.Separator)) {
		info, err := os.Stat(binary)
		if err != nil {
			return fmt.Errorf("plugin binary is not accessible: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("plugin binary points to a directory")
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("plugin binary is not executable")
		}
		return nil
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("plugin binary %q was not found on PATH", binary)
	}
	return nil
}

func (s *Server) listToolRuns(w http.ResponseWriter, r *http.Request) {
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
	runs, err := store.ListToolRuns(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, runs)
}

func (s *Server) toolRunLog(stream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		runs, err := store.ListToolRuns(r.Context(), session.ID)
		if err != nil {
			writeDBError(w, err)
			return
		}
		var logPath string
		for _, run := range runs {
			if run.ID != r.PathValue("run_id") {
				continue
			}
			if stream == "stderr" {
				logPath = run.StderrPath
			} else {
				logPath = run.StdoutPath
			}
			break
		}
		if logPath == "" || !pathInside(filepath.Dir(store.Path()), logPath) {
			writeLogUnavailable(w)
			return
		}
		body, err := os.ReadFile(logPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeLogUnavailable(w)
				return
			}
			writeDBError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	}
}

func writeLogUnavailable(w http.ResponseWriter) {
	writeJSONStatus(w, http.StatusNotFound, map[string]any{
		"available": false,
		"reason":    "log file not available",
	})
}

func pathInside(root, candidate string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func (s *Server) sessionStats(w http.ResponseWriter, r *http.Request) {
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
	stats, err := store.Stats(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) listAttackVectors(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	vectors, err := store.ListAttackVectors(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, vectors)
}

func (s *Server) listAttackGraphEdges(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	edges, err := store.ListAttackGraphEdges(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, edges)
}

func (s *Server) listCVEs(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	cves, err := store.ListCVEMatchesBySession(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, cves)
}

func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	format := models.ReportFormat(firstNonEmpty(r.URL.Query().Get("format"), string(models.ReportFormatHTML)))
	mode := models.ReportMode(firstNonEmpty(r.URL.Query().Get("mode"), string(models.ReportModeTechnical)))
	artifact, err := report.Generate(r.Context(), store, report.Options{Format: format, Mode: mode})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, artifact.Filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact.Content)
}

type llmRequest struct {
	Message string `json:"message"`
}

type llmModelsRequest struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
}

type llmModelsResponse struct {
	Models []string `json:"models"`
}

func (s *Server) llmModels(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "LLM model probing requires API key authentication") {
		return
	}
	var req llmModelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("base_url is required"))
		return
	}
	if err := s.validateLLMProbeURL(baseURL); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, llmModelsURL(baseURL), nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	apiKey := firstNonEmpty(req.APIKey, s.cfg.AppConfig.LLM.APIKey, os.Getenv("NYX_LLM_API_KEY"))
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	var client interface {
		Do(*http.Request) (*http.Response, error)
	} = http.DefaultClient
	if s.cfg.HTTPClient != nil {
		client = httpClientAdapter{s.cfg.HTTPClient}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("llm models request failed: status %d", resp.StatusCode))
		return
	}
	var decoded struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	seen := map[string]bool{}
	var models []string
	for _, model := range decoded.Data {
		id := strings.TrimSpace(model.ID)
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	for _, id := range decoded.Models {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	if len(models) == 0 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("llm endpoint returned no models"))
		return
	}
	writeJSON(w, llmModelsResponse{Models: models})
}

type httpClientAdapter struct {
	client adapters.HTTPDoer
}

func (a httpClientAdapter) Do(req *http.Request) (*http.Response, error) {
	return a.client.Do(req)
}

func llmModelsURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(base, "/models") {
		return base
	}
	if strings.HasSuffix(base, "/v1") {
		return base + "/models"
	}
	return base + "/v1/models"
}

func (s *Server) validateLLMProbeURL(baseURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("base_url must be an absolute http or https URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("base_url must use http or https")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "metadata.google.internal" {
		return fmt.Errorf("metadata service endpoints are not allowed")
	}
	if len(s.cfg.LLMAllowedHosts) > 0 && !hostAllowed(host, s.cfg.LLMAllowedHosts) {
		return fmt.Errorf("base_url host is not in the configured allowlist")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("link-local, multicast, and unspecified LLM endpoints are not allowed")
		}
	}
	return nil
}

func (s *Server) llmChat(w http.ResponseWriter, r *http.Request) {
	var req llmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("message is required"))
		return
	}
	s.runLLM(w, r, req.Message)
}

func (s *Server) llmAnalyse(w http.ResponseWriter, r *http.Request) {
	s.runLLM(w, r, "Review the completed scan. Summarize the highest-confidence risks, relevant CVEs, deterministic attack vectors, and safe follow-up checks.")
}

func (s *Server) llmHistory(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	history, err := store.ListLLMAnalyses(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, history)
}

func (s *Server) runLLM(w http.ResponseWriter, r *http.Request, prompt string) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	config := llmintel.ConfigFromSession(session)
	if !config.Configured() {
		writeError(w, http.StatusServiceUnavailable, llmintel.ErrNotConfigured)
		return
	}
	analysis, err := llmintel.NewAnalyst(store, nil, config).AnalyzeSession(r.Context(), session.ID, prompt)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, analysis)
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

func (s *Server) openSession(w http.ResponseWriter, r *http.Request) (*db.Store, models.Session, bool) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return nil, models.Session{}, false
	}
	session, err := store.GetSession(r.Context())
	if err != nil {
		store.Close()
		writeDBError(w, err)
		return nil, models.Session{}, false
	}
	return store, session, true
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		if crossOriginUnsafeRequest(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("cross-origin state-changing requests are not allowed"))
			return
		}
		if strings.TrimSpace(s.cfg.APIKey) == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/auth/login" {
			next.ServeHTTP(w, r)
			return
		}
		client := clientKey(r)
		if s.authLimited(client) {
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
			return
		}
		token := r.Header.Get("X-Nyx-API-Key")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if token == s.cfg.APIKey {
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			if cookie, err := r.Cookie(authSessionCookieName); err == nil && s.validAuthSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if token != s.cfg.APIKey {
			s.recordAuthFailure(client)
			writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid or missing API key"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

const (
	authFailureWindow     = time.Minute
	authFailureLimit      = 8
	authSessionTTL        = 12 * time.Hour
	authSessionCookieName = "nyx_session"
)

func (s *Server) createAuthSession() (string, time.Time) {
	token := models.NewID() + models.NewID()
	expires := time.Now().Add(authSessionTTL)
	s.securityMu.Lock()
	s.authSessions[token] = expires
	s.securityMu.Unlock()
	return token, expires
}

func (s *Server) validAuthSession(token string) bool {
	if token == "" {
		return false
	}
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	expires, ok := s.authSessions[token]
	if !ok {
		return false
	}
	if !expires.After(now) {
		delete(s.authSessions, token)
		return false
	}
	return true
}

func (s *Server) deleteAuthSession(token string) {
	s.securityMu.Lock()
	delete(s.authSessions, token)
	s.securityMu.Unlock()
}

func authSessionCookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     authSessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func expiredAuthSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     authSessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func (s *Server) authLimited(client string) bool {
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	failures := recentFailures(s.authFailures[client], now)
	s.authFailures[client] = failures
	return len(failures) >= authFailureLimit
}

func (s *Server) recordAuthFailure(client string) {
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	failures := recentFailures(s.authFailures[client], now)
	failures = append(failures, now)
	s.authFailures[client] = failures
}

func recentFailures(values []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-authFailureWindow)
	next := values[:0]
	for _, value := range values {
		if value.After(cutoff) {
			next = append(next, value)
		}
	}
	return next
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func crossOriginUnsafeRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return true
	}
	return !sameHost(parsed.Host, r.Host)
}

func websocketCrossOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return true
	}
	return !sameHost(parsed.Host, r.Host)
}

func sameHost(left, right string) bool {
	leftHost, leftPort := splitHostPort(left)
	rightHost, rightPort := splitHostPort(right)
	if !strings.EqualFold(leftHost, rightHost) {
		return false
	}
	return leftPort == rightPort
}

func splitHostPort(value string) (string, string) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return strings.Trim(host, "[]"), port
	}
	return strings.Trim(value, "[]"), ""
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, entry := range allowed {
		entry = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			suffix := strings.TrimPrefix(entry, "*")
			if strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
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

func validateTools(toolIDs []string) error {
	for _, id := range toolIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if strings.HasPrefix(id, "plugin:") {
			continue
		}
		if strings.HasPrefix(id, "audit/") {
			if _, ok := adapters.GetStatic(strings.TrimPrefix(id, "audit/")); !ok {
				return fmt.Errorf("unknown tool %q", id)
			}
			continue
		}
		if _, ok := adapters.Get(id); !ok {
			return fmt.Errorf("unknown tool %q", id)
		}
	}
	return nil
}

func binaryNameForTool(id string) string {
	switch id {
	case "subfinder":
		return "subfinder"
	case "dnsx":
		return "dnsx"
	case "naabu":
		return "naabu"
	case "httpx":
		return "httpx"
	case "whois":
		return "whois"
	case "waybackurls":
		return "waybackurls"
	case "nmap":
		return "nmap"
	case "ffuf":
		return "ffuf"
	case "whatweb":
		return "whatweb"
	case "nuclei-tech", "nuclei-vuln":
		return "nuclei"
	case "testssl":
		return "testssl.sh"
	case "wpscan":
		return "wpscan"
	case "droopescan":
		return "droopescan"
	case "arjun":
		return "arjun"
	case "linkfinder":
		return "linkfinder"
	case "gitleaks":
		return "gitleaks"
	case "sqlmap":
		return "sqlmap"
	case "dalfox":
		return "dalfox"
	case "ssrfmap":
		return "ssrfmap"
	case "jwt-tool":
		return "jwt_tool"
	case "nikto":
		return "nikto"
	default:
		return ""
	}
}

func installHintForTool(id, binary string) string {
	if binary == "" {
		return "Built into Nyx."
	}
	return "Install " + binary + " or configure tools." + id + " in the Nyx config."
}

func descriptionForTool(id string) string {
	descriptions := map[string]string{
		"http-probe":              "Checks whether scoped HTTP and HTTPS endpoints respond and records basic reachability evidence.",
		"security-headers":        "Inspects common browser security headers and records missing or weak protections.",
		"crtsh":                   "Queries certificate transparency data for scoped hostnames.",
		"subfinder":               "Discovers subdomains from passive sources.",
		"dnsx":                    "Resolves and validates discovered DNS names.",
		"naabu":                   "Performs scoped TCP port discovery.",
		"httpx":                   "Probes HTTP services and captures response metadata.",
		"whois":                   "Collects WHOIS registration data for scoped domains.",
		"waybackurls":             "Collects historical URLs from public archives.",
		"whatweb":                 "Fingerprints web technologies and server-side frameworks.",
		"nuclei-tech":             "Runs Nuclei technology-detection templates.",
		"testssl":                 "Checks TLS protocol and certificate configuration.",
		"graphql-introspection":   "Attempts safe GraphQL introspection discovery.",
		"openapi-discovery":       "Discovers OpenAPI and Swagger metadata endpoints.",
		"wpscan":                  "Fingerprints WordPress installations and common exposure signals.",
		"droopescan":              "Fingerprints Drupal, Joomla, and other CMS exposure signals.",
		"ffuf":                    "Runs scoped content discovery against web targets.",
		"arjun":                   "Discovers HTTP parameters with safe probing.",
		"linkfinder":              "Extracts JavaScript endpoints from scoped web responses.",
		"gitleaks":                "Scans collected code and text artifacts for secret patterns.",
		"js-secrets":              "Looks for likely secrets in JavaScript responses.",
		"cors-check":              "Checks CORS policy behavior on scoped HTTP targets.",
		"cloud-buckets":           "Checks for scoped cloud storage bucket exposure patterns.",
		"nuclei-vuln":             "Runs Nuclei vulnerability templates against scoped targets.",
		"sqlmap":                  "Runs conservative SQL injection checks with scoped inputs.",
		"dalfox":                  "Runs scoped XSS checks.",
		"ssrfmap":                 "Runs scoped SSRF checks where input evidence supports it.",
		"jwt-tool":                "Checks JWT structure and common token weaknesses.",
		"oauth-check":             "Checks OAuth and OIDC metadata for common misconfigurations.",
		"reflected-xss-check":     "Safely validates seeded query parameters for reflected XSS markers.",
		"open-redirect-check":     "Safely validates seeded redirect-like parameters without following external redirects.",
		"sqli-check":              "Safely validates seeded query parameters for SQL injection with bounded boolean and error canaries.",
		"file-inclusion-check":    "Safely validates seeded file/path parameters with bounded local hosts-file marker probes.",
		"command-injection-check": "Validates seeded command-like forms only when explicitly marked intentionally vulnerable and non-production.",
		"upload-check":            "Safely validates file upload endpoints with a harmless text marker file.",
		"idor-check":              "Checks seeded object identifier routes for adjacent-object access and optional secondary-identity replay.",
		"workflow-assist":         "Surfaces seeded high-value workflow forms and parameters for manual business-logic review without submitting state changes.",
		"csrf-check":              "Analyzes seeded state-changing forms for missing anti-CSRF token fields without submitting them.",
		"weak-session-check":      "Samples seeded session-related routes for predictable cookie or token values with tight limits.",
		"ssti-check":              "Performs safe server-side template injection checks.",
		"xxe-fuzz":                "Performs safe XML entity expansion checks without external entity exfiltration.",
		"nikto":                   "Runs Nikto web server checks against scoped HTTP services.",
		"cve-intel":               "Correlates discovered technologies with CVE intelligence.",
		"attack-vector-engine":    "Builds deterministic attack chains from normalized findings.",
		"llm-analysis":            "Adds optional local LLM annotations to findings and attack vectors.",
		"nmap":                    "Runs scoped network service detection.",
	}
	if value, ok := descriptions[id]; ok {
		return value
	}
	return "Adapter-provided scanner."
}

func homepageForTool(id string) string {
	homepages := map[string]string{
		"crtsh":        "https://crt.sh/",
		"subfinder":    "https://github.com/projectdiscovery/subfinder",
		"dnsx":         "https://github.com/projectdiscovery/dnsx",
		"naabu":        "https://github.com/projectdiscovery/naabu",
		"httpx":        "https://github.com/projectdiscovery/httpx",
		"waybackurls":  "https://github.com/tomnomnom/waybackurls",
		"whatweb":      "https://github.com/urbanadventurer/WhatWeb",
		"nuclei-tech":  "https://github.com/projectdiscovery/nuclei",
		"nuclei-vuln":  "https://github.com/projectdiscovery/nuclei",
		"testssl":      "https://github.com/testssl/testssl.sh",
		"wpscan":       "https://github.com/wpscanteam/wpscan",
		"droopescan":   "https://github.com/SamJoan/droopescan",
		"ffuf":         "https://github.com/ffuf/ffuf",
		"arjun":        "https://github.com/s0md3v/Arjun",
		"linkfinder":   "https://github.com/GerbenJavado/LinkFinder",
		"gitleaks":     "https://github.com/gitleaks/gitleaks",
		"sqlmap":       "https://github.com/sqlmapproject/sqlmap",
		"dalfox":       "https://github.com/hahwul/dalfox",
		"ssrfmap":      "https://github.com/swisskyrepo/SSRFmap",
		"jwt-tool":     "https://github.com/ticarpi/jwt_tool",
		"nikto":        "https://github.com/sullo/nikto",
		"nmap":         "https://nmap.org/",
		"llm-analysis": "https://github.com/sashabaranov/go-openai",
	}
	return homepages[id]
}

func detectVersion(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil || len(out) == 0 {
		out, err = exec.CommandContext(ctx, path, "-version").CombinedOutput()
		if err != nil || len(out) == 0 {
			return ""
		}
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return truncateString(line, 120)
}

func parametersForTool(id string) []toolParameter {
	common := []toolParameter{
		{Name: "timeout_seconds", Label: "Timeout", Type: "number", Default: 60, Description: "Per-tool timeout in seconds."},
		{Name: "extra_args", Label: "Extra Safe Args", Type: "list", Description: "Additional safe arguments for compatible subprocess tools."},
	}
	switch id {
	case "nmap":
		return []toolParameter{{Name: "timeout_seconds", Label: "Timeout", Type: "number", Default: 45, Description: "Per-tool timeout in seconds."}}
	case "ffuf":
		return append([]toolParameter{
			{Name: "wordlist", Label: "Wordlist", Type: "path", Description: "Content discovery wordlist path."},
			{Name: "matcher", Label: "Matcher", Type: "string", Description: "Use extra args for ffuf matchers such as -mc 200,204,301."},
		}, common...)
	case "nuclei-tech", "nuclei-vuln":
		return append([]toolParameter{{Name: "templates", Label: "Templates", Type: "path", Description: "Nuclei templates directory."}, {Name: "severity", Label: "Severity", Type: "enum", Options: []string{"info", "low", "medium", "high", "critical", "low,medium,high,critical", "medium,high,critical"}}}, common...)
	case "sqlmap":
		return append([]toolParameter{{Name: "level", Label: "Level", Type: "number", Default: 1, Description: "sqlmap level, clamped to 1-5."}, {Name: "risk", Label: "Risk", Type: "number", Default: 1, Description: "sqlmap risk, clamped to 1-3."}}, common...)
	case "dalfox":
		return append([]toolParameter{{Name: "blind", Label: "Blind Callback", Type: "string"}, {Name: "skip_grepping", Label: "Skip Grepping", Type: "boolean"}}, common...)
	case "command-injection-check":
		return []toolParameter{
			{Name: "allow_command_injection", Label: "Allow Command Check", Type: "boolean", Description: "Enable harmless marker command validation for explicitly safe targets."},
			{Name: "intentionally_vulnerable", Label: "Intentionally Vulnerable", Type: "boolean", Description: "Confirms the target is a lab or benchmark built for active validation."},
			{Name: "non_production", Label: "Non-production", Type: "boolean", Description: "Confirms the target is not a production system."},
		}
	default:
		return nil
	}
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func validSeverity(severity models.Severity) bool {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo:
		return true
	default:
		return false
	}
}

func pagination(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 0 {
		limit = 0
	}
	return page, limit
}

func paginate[T any](items []T, page, limit int) []T {
	if limit <= 0 {
		return items
	}
	start := (page - 1) * limit
	if start >= len(items) {
		return []T{}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func filterFindings(findings []models.Finding, cveFilter, exploitFilter string) []models.Finding {
	if cveFilter == "" && exploitFilter == "" {
		return findings
	}
	wantCVE := parseQueryBool(cveFilter)
	wantExploit := parseQueryBool(exploitFilter)
	var out []models.Finding
	for _, finding := range findings {
		hasCVE := len(finding.CVEMatches) > 0
		hasExploit := false
		for _, match := range finding.CVEMatches {
			hasExploit = hasExploit || match.ExploitAvailable
		}
		if cveFilter != "" && hasCVE != wantCVE {
			continue
		}
		if exploitFilter != "" && hasExploit != wantExploit {
			continue
		}
		out = append(out, finding)
	}
	return out
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

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
