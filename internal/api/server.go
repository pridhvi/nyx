package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	llmintel "github.com/kanini/nox/internal/llm"
	"github.com/kanini/nox/internal/models"
	"github.com/kanini/nox/internal/report"
)

type Config struct {
	Host       string
	Port       int
	SessionDir string
	APIKey     string
	HTTPClient adapters.HTTPDoer
}

type Server struct {
	cfg         Config
	scanManager *ScanManager
}

func NewServer(cfg Config) *Server {
	if cfg.SessionDir == "" {
		cfg.SessionDir = db.DefaultSessionsDir()
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("NOX_API_KEY")
	}
	return &Server{cfg: cfg, scanManager: NewScanManager(cfg.SessionDir, cfg.HTTPClient)}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Nox listening on http://%s\n", server.Addr)
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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/tools", s.tools)
	mux.HandleFunc("GET /api/sessions", s.listSessions)
	mux.HandleFunc("GET /api/sessions/{id}", s.getSession)
	mux.HandleFunc("DELETE /api/sessions/{id}", s.deleteSession)
	mux.HandleFunc("GET /api/sessions/{id}/targets", s.listTargets)
	mux.HandleFunc("GET /api/sessions/{id}/findings", s.listFindings)
	mux.HandleFunc("GET /api/sessions/{id}/tool-runs", s.listToolRuns)
	mux.HandleFunc("GET /api/sessions/{id}/stats", s.sessionStats)
	mux.HandleFunc("GET /api/sessions/{id}/vectors", s.listAttackVectors)
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
		"llm_configured":     os.Getenv("NOX_LLM_BASE_URL") != "",
		"registered_tools":   len(tools),
		"session_dir_status": readiness(dirReady),
	})
}

func (s *Server) tools(w http.ResponseWriter, r *http.Request) {
	registered := adapters.All()
	tools := make([]map[string]string, 0, len(registered))
	for _, adapter := range registered {
		tools = append(tools, map[string]string{
			"id":    adapter.ID(),
			"name":  adapter.Name(),
			"phase": string(adapter.Phase()),
		})
	}
	writeJSON(w, tools)
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
	Target        string          `json:"target"`
	Name          string          `json:"name"`
	Mode          models.ScanMode `json:"mode"`
	OutOfScope    []string        `json:"out_of_scope"`
	EnabledPhases []string        `json:"enabled_phases"`
	LLMModel      string          `json:"llm_model"`
	LLMBaseURL    string          `json:"llm_base_url"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	session, target, err := engine.NewPendingSession(engine.NewSessionInput{
		Target:        req.Target,
		Name:          req.Name,
		Mode:          req.Mode,
		OutOfScope:    req.OutOfScope,
		EnabledPhases: req.EnabledPhases,
		LLMModel:      req.LLMModel,
		LLMBaseURL:    req.LLMBaseURL,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	record, err := db.CreateSessionDB(r.Context(), s.cfg.SessionDir, session, target)
	if err != nil {
		writeDBError(w, err)
		return
	}
	s.scanManager.Start(record.Session)
	writeJSONStatus(w, http.StatusAccepted, record)
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
	if strings.TrimSpace(s.cfg.APIKey) == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-Nox-API-Key")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if token == "" {
			token = r.URL.Query().Get("api_key")
		}
		if token != s.cfg.APIKey {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid or missing API key"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func readiness(ok bool) string {
	if ok {
		return "ready"
	}
	return "unavailable"
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

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
