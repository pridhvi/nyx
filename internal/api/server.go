package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

type Config struct {
	Host       string
	Port       int
	SessionDir string
	HTTPClient adapters.HTTPDoer
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) *Server {
	if cfg.SessionDir == "" {
		cfg.SessionDir = db.DefaultSessionsDir()
	}
	return &Server{cfg: cfg}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("NOX listening on http://%s\n", server.Addr)
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
	mux.HandleFunc("GET /api/sessions/{id}/targets", s.listTargets)
	mux.HandleFunc("GET /api/scan/{id}/status", s.scanStatus)
	mux.HandleFunc("POST /api/scan/start", s.startScan)
	mux.Handle("/", http.FileServer(http.Dir("web/dist")))
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	dirReady := db.EnsureSessionsDir(s.cfg.SessionDir) == nil
	writeJSON(w, map[string]any{
		"status":       "ok",
		"time":         time.Now().UTC().Format(time.RFC3339),
		"sessions_dir": s.cfg.SessionDir,
		"db_dir_ready": dirReady,
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

type startScanRequest struct {
	Target     string          `json:"target"`
	Name       string          `json:"name"`
	Mode       models.ScanMode `json:"mode"`
	OutOfScope []string        `json:"out_of_scope"`
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	session, target, err := engine.NewPendingSession(engine.NewSessionInput{
		Target:     req.Target,
		Name:       req.Name,
		Mode:       req.Mode,
		OutOfScope: req.OutOfScope,
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
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, record.Session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	runner := engine.NewRunnerWithHTTPClient(store, s.cfg.HTTPClient)
	if err := runner.Run(r.Context(), record.Session); err != nil {
		writeDBError(w, err)
		return
	}
	updated, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	record.Session = updated
	writeJSONStatus(w, http.StatusCreated, record)
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
