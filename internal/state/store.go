package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

type MonitorRunFilter struct {
	ConfigID string
}

func DBPath(stateDir string) string {
	return filepath.Join(stateDir, "nyx-state.db")
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		database.Close()
		return nil, err
	}
	store := &Store{db: database, path: path}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at DATETIME NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS monitor_configs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			target_input TEXT NOT NULL,
			in_scope TEXT NOT NULL DEFAULT '[]',
			out_of_scope TEXT NOT NULL DEFAULT '[]',
			schedule TEXT NOT NULL,
			enabled_phases TEXT NOT NULL DEFAULT '[]',
			enabled_tools TEXT NOT NULL DEFAULT '[]',
			tool_parameters TEXT NOT NULL DEFAULT '{}',
			runner_options TEXT NOT NULL DEFAULT '{}',
			alert_on TEXT NOT NULL DEFAULT '[]',
			notification_config TEXT NOT NULL DEFAULT '{}',
			baseline_session_id TEXT NOT NULL DEFAULT '',
			last_run_at DATETIME,
			next_run_at DATETIME,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS monitor_runs (
			id TEXT PRIMARY KEY,
			config_id TEXT NOT NULL REFERENCES monitor_configs(id) ON DELETE CASCADE,
			session_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			changes_found INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			started_at DATETIME NOT NULL,
			completed_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS surface_changes (
			id TEXT PRIMARY KEY,
			monitor_run_id TEXT NOT NULL REFERENCES monitor_runs(id) ON DELETE CASCADE,
			session_id TEXT NOT NULL,
			change_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			previous_value TEXT NOT NULL DEFAULT '',
			current_value TEXT NOT NULL DEFAULT '',
			target_id TEXT NOT NULL DEFAULT '',
			finding_id TEXT NOT NULL DEFAULT '',
			alerted INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_monitor_runs_config ON monitor_runs(config_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_surface_changes_run ON surface_changes(monitor_run_id, created_at ASC)`,
		`CREATE TABLE IF NOT EXISTS burp_config (
			id TEXT PRIMARY KEY,
			base_url TEXT NOT NULL DEFAULT '',
			api_key TEXT NOT NULL DEFAULT '',
			collaborator_provider TEXT NOT NULL DEFAULT '',
			collaborator_url TEXT NOT NULL DEFAULT '',
			interactsh_token TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS burp_callbacks (
			id TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			token TEXT NOT NULL,
			finding_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',
			raw_event TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_burp_callbacks_session ON burp_callbacks(session_id, created_at DESC)`,
		`INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES ('001_monitoring', datetime('now'))`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertMonitorConfig(ctx context.Context, config models.MonitorConfig) error {
	inScope, err := json.Marshal(config.InScope)
	if err != nil {
		return err
	}
	outOfScope, err := json.Marshal(config.OutOfScope)
	if err != nil {
		return err
	}
	phases, err := json.Marshal(config.EnabledPhases)
	if err != nil {
		return err
	}
	tools, err := json.Marshal(config.EnabledTools)
	if err != nil {
		return err
	}
	parameters, err := json.Marshal(config.ToolParameters)
	if err != nil {
		return err
	}
	options, err := json.Marshal(config.RunnerOptions)
	if err != nil {
		return err
	}
	alertOn, err := json.Marshal(config.AlertOn)
	if err != nil {
		return err
	}
	notifications, err := json.Marshal(config.NotificationConfig)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO monitor_configs (
	id, name, target_input, in_scope, out_of_scope, schedule, enabled_phases,
	enabled_tools, tool_parameters, runner_options, alert_on, notification_config,
	baseline_session_id, last_run_at, next_run_at, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	target_input = excluded.target_input,
	in_scope = excluded.in_scope,
	out_of_scope = excluded.out_of_scope,
	schedule = excluded.schedule,
	enabled_phases = excluded.enabled_phases,
	enabled_tools = excluded.enabled_tools,
	tool_parameters = excluded.tool_parameters,
	runner_options = excluded.runner_options,
	alert_on = excluded.alert_on,
	notification_config = excluded.notification_config,
	baseline_session_id = excluded.baseline_session_id,
	last_run_at = excluded.last_run_at,
	next_run_at = excluded.next_run_at,
	enabled = excluded.enabled,
	updated_at = excluded.updated_at`,
		config.ID,
		config.Name,
		config.TargetInput,
		string(inScope),
		string(outOfScope),
		config.Schedule,
		string(phases),
		string(tools),
		string(parameters),
		string(options),
		string(alertOn),
		string(notifications),
		config.BaselineSessionID,
		formatTimePtr(config.LastRunAt),
		formatTimePtr(config.NextRunAt),
		boolInt(config.Enabled),
		formatTime(config.CreatedAt),
		formatTime(config.UpdatedAt),
	)
	return err
}

func (s *Store) GetMonitorConfig(ctx context.Context, id string) (models.MonitorConfig, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, target_input, in_scope, out_of_scope, schedule, enabled_phases,
       enabled_tools, tool_parameters, runner_options, alert_on, notification_config,
       baseline_session_id, last_run_at, next_run_at, enabled, created_at, updated_at
FROM monitor_configs
WHERE id = ?`, id)
	return scanMonitorConfig(row)
}

func (s *Store) ListMonitorConfigs(ctx context.Context) ([]models.MonitorConfig, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, target_input, in_scope, out_of_scope, schedule, enabled_phases,
       enabled_tools, tool_parameters, runner_options, alert_on, notification_config,
       baseline_session_id, last_run_at, next_run_at, enabled, created_at, updated_at
FROM monitor_configs
ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var configs []models.MonitorConfig
	for rows.Next() {
		config, err := scanMonitorConfig(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	return configs, rows.Err()
}

func (s *Store) DeleteMonitorConfig(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM monitor_configs WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateMonitorEnabled(ctx context.Context, id string, enabled bool, nextRunAt *time.Time) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE monitor_configs
SET enabled = ?, next_run_at = ?, updated_at = ?
WHERE id = ?`,
		boolInt(enabled), formatTimePtr(nextRunAt), formatTime(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateMonitorRunMetadata(ctx context.Context, id, baselineSessionID string, lastRunAt, nextRunAt *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE monitor_configs
SET baseline_session_id = CASE WHEN ? != '' THEN ? ELSE baseline_session_id END,
    last_run_at = COALESCE(?, last_run_at),
    next_run_at = ?,
    updated_at = ?
WHERE id = ?`,
		baselineSessionID, baselineSessionID, formatTimePtr(lastRunAt), formatTimePtr(nextRunAt), formatTime(time.Now().UTC()), id)
	return err
}

func (s *Store) SetMonitorBaseline(ctx context.Context, id, baselineSessionID string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE monitor_configs
SET baseline_session_id = ?, updated_at = ?
WHERE id = ?`,
		baselineSessionID, formatTime(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (s *Store) InsertMonitorRun(ctx context.Context, run models.MonitorRun) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO monitor_runs (id, config_id, session_id, status, changes_found, error, started_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.ConfigID,
		run.SessionID,
		string(run.Status),
		boolInt(run.ChangesFound),
		run.Error,
		formatTime(run.StartedAt),
		formatTimePtr(run.CompletedAt),
	)
	return err
}

func (s *Store) UpdateMonitorRun(ctx context.Context, run models.MonitorRun) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE monitor_runs
SET session_id = ?, status = ?, changes_found = ?, error = ?, completed_at = ?
WHERE id = ?`,
		run.SessionID,
		string(run.Status),
		boolInt(run.ChangesFound),
		run.Error,
		formatTimePtr(run.CompletedAt),
		run.ID,
	)
	return err
}

func (s *Store) ListMonitorRuns(ctx context.Context, filter MonitorRunFilter) ([]models.MonitorRun, error) {
	query := `SELECT id, config_id, session_id, status, changes_found, error, started_at, completed_at FROM monitor_runs`
	args := []any{}
	if filter.ConfigID != "" {
		query += ` WHERE config_id = ?`
		args = append(args, filter.ConfigID)
	}
	query += ` ORDER BY started_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []models.MonitorRun
	for rows.Next() {
		run, err := scanMonitorRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) GetMonitorRun(ctx context.Context, id string) (models.MonitorRun, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, config_id, session_id, status, changes_found, error, started_at, completed_at FROM monitor_runs WHERE id = ?`, id)
	return scanMonitorRun(row)
}

func (s *Store) InsertSurfaceChange(ctx context.Context, change models.SurfaceChange) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO surface_changes (
	id, monitor_run_id, session_id, change_type, severity, description, previous_value,
	current_value, target_id, finding_id, alerted, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		change.ID,
		change.MonitorRunID,
		change.SessionID,
		string(change.ChangeType),
		string(change.Severity),
		change.Description,
		change.PreviousValue,
		change.CurrentValue,
		change.TargetID,
		change.FindingID,
		boolInt(change.Alerted),
		formatTime(change.CreatedAt),
	)
	return err
}

func (s *Store) InsertSurfaceChanges(ctx context.Context, changes []models.SurfaceChange) error {
	for _, change := range changes {
		if err := s.InsertSurfaceChange(ctx, change); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListSurfaceChanges(ctx context.Context, runID string) ([]models.SurfaceChange, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, monitor_run_id, session_id, change_type, severity, description, previous_value,
       current_value, target_id, finding_id, alerted, created_at
FROM surface_changes
WHERE monitor_run_id = ?
ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var changes []models.SurfaceChange
	for rows.Next() {
		change, err := scanSurfaceChange(rows)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

func (s *Store) ListSurfaceChangesByConfig(ctx context.Context, configID string) ([]models.SurfaceChange, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.id, c.monitor_run_id, c.session_id, c.change_type, c.severity, c.description,
       c.previous_value, c.current_value, c.target_id, c.finding_id, c.alerted, c.created_at
FROM surface_changes c
JOIN monitor_runs r ON r.id = c.monitor_run_id
WHERE r.config_id = ?
ORDER BY c.created_at DESC`, configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var changes []models.SurfaceChange
	for rows.Next() {
		change, err := scanSurfaceChange(rows)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

func (s *Store) MarkSurfaceChangeAlerted(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE surface_changes SET alerted = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return db.ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMonitorConfig(row rowScanner) (models.MonitorConfig, error) {
	var config models.MonitorConfig
	var inScope, outOfScope, phases, tools, parameters, options, alertOn, notifications string
	var lastRun, nextRun sql.NullString
	var createdAt, updatedAt string
	var enabled int
	err := row.Scan(
		&config.ID,
		&config.Name,
		&config.TargetInput,
		&inScope,
		&outOfScope,
		&config.Schedule,
		&phases,
		&tools,
		&parameters,
		&options,
		&alertOn,
		&notifications,
		&config.BaselineSessionID,
		&lastRun,
		&nextRun,
		&enabled,
		&createdAt,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return models.MonitorConfig{}, db.ErrNotFound
	}
	if err != nil {
		return models.MonitorConfig{}, err
	}
	config.Enabled = enabled != 0
	config.LastRunAt = parseNullTime(lastRun)
	config.NextRunAt = parseNullTime(nextRun)
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return models.MonitorConfig{}, err
	}
	parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return models.MonitorConfig{}, err
	}
	config.CreatedAt = parsedCreatedAt
	config.UpdatedAt = parsedUpdatedAt
	if err := json.Unmarshal([]byte(inScope), &config.InScope); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(outOfScope), &config.OutOfScope); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(phases), &config.EnabledPhases); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(tools), &config.EnabledTools); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(parameters), &config.ToolParameters); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(options), &config.RunnerOptions); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(alertOn), &config.AlertOn); err != nil {
		return models.MonitorConfig{}, err
	}
	if err := json.Unmarshal([]byte(notifications), &config.NotificationConfig); err != nil {
		return models.MonitorConfig{}, err
	}
	return config, nil
}

func scanMonitorRun(row rowScanner) (models.MonitorRun, error) {
	var run models.MonitorRun
	var status string
	var changesFound int
	var completed sql.NullString
	var startedAt string
	err := row.Scan(&run.ID, &run.ConfigID, &run.SessionID, &status, &changesFound, &run.Error, &startedAt, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return models.MonitorRun{}, db.ErrNotFound
	}
	if err != nil {
		return models.MonitorRun{}, err
	}
	run.Status = models.MonitorStatus(status)
	run.ChangesFound = changesFound != 0
	run.CompletedAt = parseNullTime(completed)
	parsedStartedAt, err := time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return models.MonitorRun{}, err
	}
	run.StartedAt = parsedStartedAt
	return run, nil
}

func scanSurfaceChange(row rowScanner) (models.SurfaceChange, error) {
	var change models.SurfaceChange
	var changeType, severity string
	var alerted int
	var createdAt string
	err := row.Scan(
		&change.ID,
		&change.MonitorRunID,
		&change.SessionID,
		&changeType,
		&severity,
		&change.Description,
		&change.PreviousValue,
		&change.CurrentValue,
		&change.TargetID,
		&change.FindingID,
		&alerted,
		&createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return models.SurfaceChange{}, db.ErrNotFound
	}
	if err != nil {
		return models.SurfaceChange{}, err
	}
	change.ChangeType = models.SurfaceChangeType(changeType)
	change.Severity = models.Severity(severity)
	change.Alerted = alerted != 0
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return models.SurfaceChange{}, err
	}
	change.CreatedAt = parsedCreatedAt
	return change, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

func parseNullTime(value sql.NullString) *time.Time {
	if !value.Valid || value.String == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &parsed
}
