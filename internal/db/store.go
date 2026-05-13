package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
	_ "modernc.org/sqlite"
)

const migrationVersion = "001_initial"

var ErrNotFound = errors.New("not found")

type Store struct {
	db   *sql.DB
	path string
}

type SessionRecord struct {
	Session models.Session `json:"session"`
	DBPath  string         `json:"db_path"`
}

type SessionStats struct {
	SessionID      string         `json:"session_id"`
	TargetCount    int            `json:"target_count"`
	FindingCount   int            `json:"finding_count"`
	ToolRunCount   int            `json:"tool_run_count"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

type FindingFilter struct {
	Severity string
	ToolID   string
	Type     string
}

func DefaultSessionsDir() string {
	return filepath.Join(".nox", "sessions")
}

func EnsureSessionsDir(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

func SessionDBPath(dir, sessionID string) (string, error) {
	if !validSessionID(sessionID) {
		return "", fmt.Errorf("invalid session id %q", sessionID)
	}
	return filepath.Join(dir, sessionID+".db"), nil
}

func CreateSessionDB(ctx context.Context, dir string, session models.Session, target models.Target) (SessionRecord, error) {
	if err := EnsureSessionsDir(dir); err != nil {
		return SessionRecord{}, err
	}
	path, err := SessionDBPath(dir, session.ID)
	if err != nil {
		return SessionRecord{}, err
	}
	store, err := Open(ctx, path)
	if err != nil {
		return SessionRecord{}, err
	}
	defer store.Close()
	if err := store.InsertSession(ctx, session); err != nil {
		return SessionRecord{}, err
	}
	if err := store.InsertTarget(ctx, target); err != nil {
		return SessionRecord{}, err
	}
	if err := store.UpdateSessionCounts(ctx, session.ID); err != nil {
		return SessionRecord{}, err
	}
	session.TargetCount = 1
	return SessionRecord{Session: session, DBPath: path}, nil
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &Store{db: database, path: path}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) InsertSession(ctx context.Context, session models.Session) error {
	inScope, err := json.Marshal(session.InScope)
	if err != nil {
		return err
	}
	outOfScope, err := json.Marshal(session.OutOfScope)
	if err != nil {
		return err
	}
	phases, err := json.Marshal(session.EnabledPhases)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO sessions (
	id, name, status, mode, target_input, in_scope, out_of_scope, enabled_phases,
	llm_model, llm_base_url, target_count, finding_count, started_at, completed_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.Name,
		string(session.Status),
		string(session.Mode),
		session.TargetInput,
		string(inScope),
		string(outOfScope),
		string(phases),
		session.LLMModel,
		session.LLMBaseURL,
		session.TargetCount,
		session.FindingCount,
		formatTimePtr(session.StartedAt),
		formatTimePtr(session.CompletedAt),
		formatTime(session.CreatedAt),
	)
	return err
}

func (s *Store) InsertTarget(ctx context.Context, target models.Target) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO targets (id, session_id, host, ip, port, protocol, is_alive, discovered_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		target.ID,
		target.SessionID,
		target.Host,
		target.IP,
		target.Port,
		target.Protocol,
		target.IsAlive,
		target.DiscoveredBy,
		formatTime(target.CreatedAt),
	)
	return err
}

func (s *Store) UpdateTarget(ctx context.Context, target models.Target) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE targets
SET host = ?, ip = ?, port = ?, protocol = ?, is_alive = ?, discovered_by = ?
WHERE id = ? AND session_id = ?`,
		target.Host,
		target.IP,
		target.Port,
		target.Protocol,
		target.IsAlive,
		target.DiscoveredBy,
		target.ID,
		target.SessionID,
	)
	return err
}

func (s *Store) InsertFinding(ctx context.Context, finding models.Finding) error {
	tags, err := json.Marshal(finding.Tags)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO findings (
	id, session_id, target_id, tool_id, type, severity, confidence, cvss_score,
	title, description, remediation, url, parameter, method, evidence_raw,
	evidence_normalized, tags, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID,
		finding.SessionID,
		finding.TargetID,
		finding.ToolID,
		string(finding.Type),
		string(finding.Severity),
		finding.Confidence,
		finding.CVSSScore,
		finding.Title,
		finding.Description,
		finding.Remediation,
		finding.URL,
		finding.Parameter,
		finding.Method,
		finding.EvidenceRaw,
		finding.EvidenceNormalized,
		string(tags),
		formatTime(finding.CreatedAt),
	)
	return err
}

func (s *Store) InsertToolRun(ctx context.Context, run models.ToolRun) error {
	args, err := json.Marshal(run.Args)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO tool_runs (
	id, session_id, target_id, tool_id, args, stdout_raw, stderr_raw, exit_code,
	duration_ms, finding_count, normalized_at, started_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.SessionID,
		nullableString(run.TargetID),
		run.ToolID,
		string(args),
		run.StdoutRaw,
		run.StderrRaw,
		run.ExitCode,
		run.DurationMS,
		run.FindingCount,
		formatTimePtr(run.NormalizedAt),
		formatTime(run.StartedAt),
	)
	return err
}

func (s *Store) UpdateSessionStatus(ctx context.Context, sessionID string, status models.SessionStatus, startedAt, completedAt *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE sessions
SET status = ?, started_at = COALESCE(?, started_at), completed_at = COALESCE(?, completed_at)
WHERE id = ?`,
		string(status),
		formatTimePtr(startedAt),
		formatTimePtr(completedAt),
		sessionID,
	)
	return err
}

func (s *Store) GetSession(ctx context.Context) (models.Session, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, status, mode, target_input, in_scope, out_of_scope, enabled_phases,
       llm_model, llm_base_url, target_count, finding_count, started_at, completed_at, created_at
FROM sessions
ORDER BY created_at ASC
LIMIT 1`)
	return scanSession(row)
}

func (s *Store) ListTargets(ctx context.Context, sessionID string) ([]models.Target, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, host, ip, port, protocol, is_alive, discovered_by, created_at
FROM targets
WHERE session_id = ?
ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []models.Target
	for rows.Next() {
		target, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context, sessionID string, filter FindingFilter) ([]models.Finding, error) {
	query := `
SELECT id, session_id, target_id, tool_id, type, severity, confidence, cvss_score,
       title, description, remediation, url, parameter, method, evidence_raw,
       evidence_normalized, tags, created_at
FROM findings
WHERE session_id = ?`
	args := []any{sessionID}
	if filter.Severity != "" {
		query += ` AND severity = ?`
		args = append(args, filter.Severity)
	}
	if filter.ToolID != "" {
		query += ` AND tool_id = ?`
		args = append(args, filter.ToolID)
	}
	if filter.Type != "" {
		query += ` AND type = ?`
		args = append(args, filter.Type)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []models.Finding
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) ListToolRuns(ctx context.Context, sessionID string) ([]models.ToolRun, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, COALESCE(target_id, ''), tool_id, args, stdout_raw, stderr_raw,
       exit_code, duration_ms, finding_count, normalized_at, started_at
FROM tool_runs
WHERE session_id = ?
ORDER BY started_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []models.ToolRun
	for rows.Next() {
		run, err := scanToolRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) Stats(ctx context.Context, sessionID string) (SessionStats, error) {
	stats := SessionStats{SessionID: sessionID, SeverityCounts: map[string]int{}}
	err := s.db.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM targets WHERE session_id = ?),
  (SELECT COUNT(*) FROM findings WHERE session_id = ?),
  (SELECT COUNT(*) FROM tool_runs WHERE session_id = ?)`,
		sessionID, sessionID, sessionID,
	).Scan(&stats.TargetCount, &stats.FindingCount, &stats.ToolRunCount)
	if err != nil {
		return SessionStats{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM findings WHERE session_id = ? GROUP BY severity`, sessionID)
	if err != nil {
		return SessionStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return SessionStats{}, err
		}
		stats.SeverityCounts[severity] = count
	}
	return stats, rows.Err()
}

func (s *Store) UpdateSessionCounts(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE sessions
SET target_count = (SELECT COUNT(*) FROM targets WHERE session_id = ?),
    finding_count = (SELECT COUNT(*) FROM findings WHERE session_id = ?)
WHERE id = ?`, sessionID, sessionID, sessionID)
	return err
}

func ListSessions(ctx context.Context, dir string) ([]SessionRecord, error) {
	if err := EnsureSessionsDir(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	records := make([]SessionRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".db" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		store, err := Open(ctx, path)
		if err != nil {
			continue
		}
		session, err := store.GetSession(ctx)
		closeErr := store.Close()
		if err != nil || closeErr != nil {
			continue
		}
		records = append(records, SessionRecord{Session: session, DBPath: path})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Session.CreatedAt.After(records[j].Session.CreatedAt)
	})
	return records, nil
}

func OpenSession(ctx context.Context, dir, sessionID string) (*Store, error) {
	path, err := SessionDBPath(dir, sessionID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return Open(ctx, path)
}

func DeleteSession(ctx context.Context, dir, sessionID string) error {
	store, err := OpenSession(ctx, dir, sessionID)
	if err != nil {
		return err
	}
	if _, err := store.GetSession(ctx); err != nil {
		store.Close()
		return err
	}
	path := store.Path()
	if err := store.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA journal_mode = WAL`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		return err
	}
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, migrationVersion).Scan(&existing)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	body, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, migrationVersion, formatTime(time.Now().UTC())); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(row rowScanner) (models.Session, error) {
	var session models.Session
	var inScope, outOfScope, phases string
	var startedAt, completedAt sql.NullString
	var createdAt string
	err := row.Scan(
		&session.ID,
		&session.Name,
		&session.Status,
		&session.Mode,
		&session.TargetInput,
		&inScope,
		&outOfScope,
		&phases,
		&session.LLMModel,
		&session.LLMBaseURL,
		&session.TargetCount,
		&session.FindingCount,
		&startedAt,
		&completedAt,
		&createdAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Session{}, ErrNotFound
		}
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(inScope), &session.InScope); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(outOfScope), &session.OutOfScope); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(phases), &session.EnabledPhases); err != nil {
		return models.Session{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.Session{}, err
	}
	session.CreatedAt = created
	if startedAt.Valid {
		started, err := parseTime(startedAt.String)
		if err != nil {
			return models.Session{}, err
		}
		session.StartedAt = &started
	}
	if completedAt.Valid {
		completed, err := parseTime(completedAt.String)
		if err != nil {
			return models.Session{}, err
		}
		session.CompletedAt = &completed
	}
	return session, nil
}

func scanTarget(row rowScanner) (models.Target, error) {
	var target models.Target
	var createdAt string
	err := row.Scan(
		&target.ID,
		&target.SessionID,
		&target.Host,
		&target.IP,
		&target.Port,
		&target.Protocol,
		&target.IsAlive,
		&target.DiscoveredBy,
		&createdAt,
	)
	if err != nil {
		return models.Target{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.Target{}, err
	}
	target.CreatedAt = created
	return target, nil
}

func scanFinding(row rowScanner) (models.Finding, error) {
	var finding models.Finding
	var createdAt string
	var tags string
	err := row.Scan(
		&finding.ID,
		&finding.SessionID,
		&finding.TargetID,
		&finding.ToolID,
		&finding.Type,
		&finding.Severity,
		&finding.Confidence,
		&finding.CVSSScore,
		&finding.Title,
		&finding.Description,
		&finding.Remediation,
		&finding.URL,
		&finding.Parameter,
		&finding.Method,
		&finding.EvidenceRaw,
		&finding.EvidenceNormalized,
		&tags,
		&createdAt,
	)
	if err != nil {
		return models.Finding{}, err
	}
	if err := json.Unmarshal([]byte(tags), &finding.Tags); err != nil {
		return models.Finding{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.Finding{}, err
	}
	finding.CreatedAt = created
	return finding, nil
}

func scanToolRun(row rowScanner) (models.ToolRun, error) {
	var run models.ToolRun
	var args string
	var normalizedAt sql.NullString
	var startedAt string
	err := row.Scan(
		&run.ID,
		&run.SessionID,
		&run.TargetID,
		&run.ToolID,
		&args,
		&run.StdoutRaw,
		&run.StderrRaw,
		&run.ExitCode,
		&run.DurationMS,
		&run.FindingCount,
		&normalizedAt,
		&startedAt,
	)
	if err != nil {
		return models.ToolRun{}, err
	}
	if err := json.Unmarshal([]byte(args), &run.Args); err != nil {
		return models.ToolRun{}, err
	}
	if normalizedAt.Valid {
		normalized, err := parseTime(normalizedAt.String)
		if err != nil {
			return models.ToolRun{}, err
		}
		run.NormalizedAt = &normalized
	}
	started, err := parseTime(startedAt)
	if err != nil {
		return models.ToolRun{}, err
	}
	run.StartedAt = started
	return run, nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func parseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

func validSessionID(sessionID string) bool {
	if sessionID == "" || sessionID != filepath.Base(sessionID) {
		return false
	}
	for _, r := range sessionID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
