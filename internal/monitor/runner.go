package monitor

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/state"
)

type Runner struct {
	State      *state.Store
	SessionDir string
	HTTPClient adapters.HTTPDoer
}

func (r Runner) RunNow(ctx context.Context, configID string) (models.MonitorRun, []models.SurfaceChange, error) {
	config, err := r.State.GetMonitorConfig(ctx, configID)
	if err != nil {
		return models.MonitorRun{}, nil, err
	}
	started := time.Now().UTC()
	run := models.MonitorRun{
		ID:        models.NewID(),
		ConfigID:  config.ID,
		Status:    models.MonitorRunStatusRunning,
		StartedAt: started,
	}
	if err := r.State.InsertMonitorRun(ctx, run); err != nil {
		return models.MonitorRun{}, nil, err
	}
	changes, scanErr := r.run(ctx, config, &run)
	completed := time.Now().UTC()
	run.CompletedAt = &completed
	run.ChangesFound = len(changes) > 0
	if scanErr != nil {
		run.Status = models.MonitorRunStatusFailed
		run.Error = scanErr.Error()
	} else {
		run.Status = models.MonitorRunStatusCompleted
	}
	if err := r.State.UpdateMonitorRun(context.WithoutCancel(ctx), run); err != nil && scanErr == nil {
		scanErr = err
	}
	if scanErr == nil {
		if err := r.State.InsertSurfaceChanges(context.WithoutCancel(ctx), changes); err != nil {
			scanErr = err
		}
	}
	next, nextErr := NextRun(config.Schedule, completed)
	if nextErr != nil {
		slog.Warn("calculate next monitor run", "config_id", config.ID, "error", nextErr)
	}
	nextPtr := &next
	if nextErr != nil {
		nextPtr = nil
	}
	baseline := ""
	if config.BaselineSessionID == "" && run.SessionID != "" && scanErr == nil {
		baseline = run.SessionID
	}
	_ = r.State.UpdateMonitorRunMetadata(context.WithoutCancel(ctx), config.ID, baseline, &completed, nextPtr)
	return run, changes, scanErr
}

func (r Runner) run(ctx context.Context, config models.MonitorConfig, run *models.MonitorRun) ([]models.SurfaceChange, error) {
	input := engine.NewSessionInput{
		Target:         config.TargetInput,
		Name:           "Monitor: " + config.Name,
		Mode:           models.ScanModeActive,
		OutOfScope:     config.OutOfScope,
		EnabledPhases:  config.EnabledPhases,
		EnabledTools:   config.EnabledTools,
		ToolParameters: config.ToolParameters,
		RunnerOptions:  config.RunnerOptions,
	}
	session, targets, err := engine.NewPendingSessionWithTargets(input)
	if err != nil {
		return nil, err
	}
	if len(config.InScope) > 0 {
		session.InScope = config.InScope
	}
	record, err := db.CreateSessionDBWithTargets(ctx, r.SessionDir, session, targets)
	if err != nil {
		return nil, err
	}
	run.SessionID = record.Session.ID
	if err := r.State.UpdateMonitorRun(ctx, *run); err != nil {
		return nil, err
	}
	store, err := db.OpenSession(ctx, r.SessionDir, record.Session.ID)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	options := engine.RunnerOptions{
		GlobalConcurrency:  config.RunnerOptions.Concurrency,
		PerToolConcurrency: config.RunnerOptions.PerToolConcurrency,
		ToolDelay:          time.Duration(config.RunnerOptions.ToolDelayMS) * time.Millisecond,
		ToolTimeout:        time.Duration(config.RunnerOptions.ToolTimeoutSeconds) * time.Second,
		ProxyURL:           config.RunnerOptions.ProxyURL,
	}
	runner := engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), r.HTTPClient, options)
	if err := runner.Run(ctx, record.Session); err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.BaselineSessionID) == "" {
		return nil, nil
	}
	return Differ{SessionDir: r.SessionDir}.DiffSessions(ctx, config.BaselineSessionID, record.Session.ID, run.ID)
}
