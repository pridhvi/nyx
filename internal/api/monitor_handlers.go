package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/monitor"
	"github.com/pridhvi/nyx/internal/state"
)

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
