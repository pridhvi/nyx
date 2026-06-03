package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	_ "modernc.org/sqlite"
)

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
	SessionID           string         `json:"session_id"`
	TargetCount         int            `json:"target_count"`
	FindingCount        int            `json:"finding_count"`
	StaticFindingCount  int            `json:"static_finding_count"`
	DynamicFindingCount int            `json:"dynamic_finding_count"`
	ConfirmedByBoth     int            `json:"confirmed_by_both"`
	SourceFindingCount  int            `json:"source_finding_count"`
	ToolRunCount        int            `json:"tool_run_count"`
	SeverityCounts      map[string]int `json:"severity_counts"`
}

type FindingFilter struct {
	Severity string
	ToolID   string
	Type     string
	Status   string
	Origin   string
}

type SourceFindingFilter struct {
	Kind string
}

func DefaultSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".nyx", "sessions")
	}
	return filepath.Join(home, ".nyx", "sessions")
}

func EnsureSessionsDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

func SessionDBPath(dir, sessionID string) (string, error) {
	if !validSessionID(sessionID) {
		return "", fmt.Errorf("invalid session id %q", sessionID)
	}
	root, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(root, sessionID, "session.db")
	if !pathInsideOrEqual(root, candidate) {
		return "", fmt.Errorf("session path escapes session directory")
	}
	return candidate, nil
}

func CreateSessionDB(ctx context.Context, dir string, session models.Session, target models.Target) (SessionRecord, error) {
	return CreateSessionDBWithTargets(ctx, dir, session, []models.Target{target})
}

func CreateSessionDBWithTargets(ctx context.Context, dir string, session models.Session, targets []models.Target) (SessionRecord, error) {
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
	for _, target := range targets {
		if err := store.InsertTarget(ctx, target); err != nil {
			return SessionRecord{}, err
		}
	}
	if err := store.UpdateSessionCounts(ctx, session.ID); err != nil {
		return SessionRecord{}, err
	}
	session.TargetCount = len(targets)
	return SessionRecord{Session: session, DBPath: path}, nil
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
	tools, err := json.Marshal(session.EnabledTools)
	if err != nil {
		return err
	}
	parameters, err := json.Marshal(session.ToolParameters)
	if err != nil {
		return err
	}
	runnerOptions, err := json.Marshal(session.RunnerOptions)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO sessions (
	id, name, status, mode, workload_mode, target_input, source_path, in_scope, out_of_scope, enabled_phases,
	enabled_tools, tool_parameters, runner_options, llm_model, llm_base_url,
	target_count, finding_count, started_at, completed_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.Name,
		string(session.Status),
		string(session.Mode),
		string(firstWorkloadMode(session.WorkloadMode)),
		session.TargetInput,
		session.SourcePath,
		string(inScope),
		string(outOfScope),
		string(phases),
		string(tools),
		string(parameters),
		string(runnerOptions),
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
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
	); err != nil {
		tx.Rollback()
		return err
	}
	for _, technology := range target.Technologies {
		if err := insertTechnologyTx(ctx, tx, technology); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpdateTarget(ctx context.Context, target models.Target) error {
	result, err := s.db.ExecContext(ctx, `
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
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return s.InsertTarget(ctx, target)
	}
	return nil
}

func (s *Store) InsertFinding(ctx context.Context, finding models.Finding) error {
	tags, err := json.Marshal(finding.Tags)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO findings (
	id, session_id, target_id, tool_id, type, severity, confidence, cvss_score,
	title, description, remediation, url, parameter, method, evidence_raw,
	evidence_normalized, code_context, flow_summary, status, notes, tags, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID,
		finding.SessionID,
		nullableString(finding.TargetID),
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
		finding.CodeContext,
		finding.FlowSummary,
		firstNonEmpty(finding.Status, "pending"),
		finding.Notes,
		string(tags),
		formatTime(finding.CreatedAt),
	); err != nil {
		tx.Rollback()
		return err
	}
	if finding.HTTPEvidence != nil {
		evidence := *finding.HTTPEvidence
		if evidence.FindingID == "" {
			evidence.FindingID = finding.ID
		}
		if err := insertHTTPEvidenceTx(ctx, tx, evidence); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, match := range finding.CVEMatches {
		if match.FindingID == "" {
			match.FindingID = finding.ID
		}
		if err := insertCVEMatchTx(ctx, tx, match); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpdateFinding(ctx context.Context, findingID string, severity models.Severity, remediation string) error {
	query := `UPDATE findings SET id = id`
	args := []any{}
	if severity != "" {
		query += `, severity = ?`
		args = append(args, string(severity))
	}
	if remediation != "" {
		query += `, remediation = ?`
		args = append(args, remediation)
	}
	query += ` WHERE id = ?`
	args = append(args, findingID)
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateFindingAuditFields(ctx context.Context, finding models.Finding) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE findings
SET severity = ?, confidence = ?, description = ?, remediation = ?,
    evidence_normalized = ?, code_context = ?, flow_summary = ?, status = ?, notes = ?
WHERE id = ? AND session_id = ?`,
		string(finding.Severity),
		finding.Confidence,
		finding.Description,
		finding.Remediation,
		finding.EvidenceNormalized,
		finding.CodeContext,
		finding.FlowSummary,
		firstNonEmpty(finding.Status, "pending"),
		finding.Notes,
		finding.ID,
		finding.SessionID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) InsertHTTPEvidence(ctx context.Context, evidence models.HTTPEvidence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := insertHTTPEvidenceTx(ctx, tx, evidence); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) InsertTechnology(ctx context.Context, technology models.Technology) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := insertTechnologyTx(ctx, tx, technology); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) InsertCVEMatch(ctx context.Context, match models.CVEMatch) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := insertCVEMatchTx(ctx, tx, match); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) InsertAttackVector(ctx context.Context, vector models.AttackVector) error {
	steps, err := json.Marshal(vector.Steps)
	if err != nil {
		return err
	}
	prereqs, err := json.Marshal(vector.PrereqFindingIDs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO attack_vectors (
	id, session_id, title, description, narrative, owasp_category, severity,
	confidence, steps, prereq_finding_ids, llm_reviewed, llm_notes, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vector.ID,
		vector.SessionID,
		vector.Title,
		vector.Description,
		vector.Narrative,
		vector.OWASPCategory,
		string(vector.Severity),
		vector.Confidence,
		string(steps),
		string(prereqs),
		vector.LLMReviewed,
		vector.LLMNotes,
		formatTime(vector.CreatedAt),
	)
	return err
}

func (s *Store) UpdateAttackVectorLLMReview(ctx context.Context, vectorID string, reviewed bool, notes string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE attack_vectors
SET llm_reviewed = ?, llm_notes = ?
WHERE id = ?`,
		reviewed,
		notes,
		vectorID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) InsertLLMAnalysis(ctx context.Context, analysis models.LLMAnalysis) error {
	messages, err := json.Marshal(analysis.Messages)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO llm_analyses (
	id, session_id, model_id, prompt_summary, messages, total_tokens, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		analysis.ID,
		analysis.SessionID,
		analysis.ModelID,
		analysis.PromptSummary,
		string(messages),
		analysis.TotalTokens,
		formatTime(analysis.CreatedAt),
	)
	return err
}

func (s *Store) UpsertPlugin(ctx context.Context, plugin models.PluginRecord) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO plugins (id, name, binary, sha256, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	binary = excluded.binary,
	sha256 = excluded.sha256,
	enabled = excluded.enabled,
	updated_at = excluded.updated_at`,
		plugin.ID,
		plugin.Name,
		plugin.Binary,
		plugin.SHA256,
		plugin.Enabled,
		formatTime(plugin.CreatedAt),
		formatTime(plugin.UpdatedAt),
	)
	return err
}

func (s *Store) DeletePlugin(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM plugins WHERE name = ?`, name)
	return err
}

func insertHTTPEvidenceTx(ctx context.Context, tx *sql.Tx, evidence models.HTTPEvidence) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO http_evidence (
	id, finding_id, request_raw, response_raw, status_code, response_time
) VALUES (?, ?, ?, ?, ?, ?)`,
		models.NewID(),
		evidence.FindingID,
		evidence.RequestRaw,
		evidence.ResponseRaw,
		evidence.StatusCode,
		evidence.ResponseTime,
	)
	return err
}

func insertTechnologyTx(ctx context.Context, tx *sql.Tx, technology models.Technology) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO technologies (
	id, target_id, name, version, category, confidence, source_tool
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		technology.ID,
		technology.TargetID,
		technology.Name,
		technology.Version,
		technology.Category,
		technology.Confidence,
		technology.SourceTool,
	)
	return err
}

func insertCVEMatchTx(ctx context.Context, tx *sql.Tx, match models.CVEMatch) error {
	references, err := json.Marshal(match.References)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO cve_matches (
	id, session_id, finding_id, technology_id, cve_id, cvss_v3_score, cvss_v3_vector,
	description, package_name, package_version, affected_version, fixed_version, patch_available,
	exploit_available, "references", source, confidence_score
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		match.ID,
		match.SessionID,
		nullableString(match.FindingID),
		nullableString(match.TechnologyID),
		match.CVEID,
		match.CVSSv3Score,
		match.CVSSv3Vector,
		match.Description,
		match.PackageName,
		match.PackageVersion,
		match.AffectedVersion,
		match.FixedVersion,
		match.PatchAvailable,
		match.ExploitAvailable,
		string(references),
		match.Source,
		match.ConfidenceScore,
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
	id, session_id, target_id, tool_id, args, stdout_path, stderr_path, exit_code,
	duration_ms, finding_count, normalized_at, started_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.SessionID,
		nullableString(run.TargetID),
		run.ToolID,
		string(args),
		run.StdoutPath,
		run.StderrPath,
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
       workload_mode, source_path, enabled_tools, tool_parameters, runner_options, llm_model, llm_base_url,
       target_count, finding_count, started_at, completed_at, created_at
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
		target.Technologies, err = s.ListTechnologies(ctx, target.ID)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Store) ListTechnologies(ctx context.Context, targetID string) ([]models.Technology, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, target_id, name, version, category, confidence, source_tool
FROM technologies
WHERE target_id = ?
ORDER BY created_at ASC`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var technologies []models.Technology
	for rows.Next() {
		technology, err := scanTechnology(rows)
		if err != nil {
			return nil, err
		}
		technologies = append(technologies, technology)
	}
	return technologies, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context, sessionID string, filter FindingFilter) ([]models.Finding, error) {
	query := `
SELECT id, session_id, COALESCE(target_id, ''), tool_id, type, severity, confidence, cvss_score,
       title, description, remediation, url, parameter, method, evidence_raw,
       evidence_normalized, code_context, flow_summary, status, notes, tags, created_at
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
	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, filter.Status)
	}
	switch filter.Origin {
	case "static":
		query += ` AND tool_id LIKE 'audit/%'`
	case "dynamic":
		query += ` AND tool_id NOT LIKE 'audit/%'`
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
		evidence, err := s.GetHTTPEvidence(ctx, finding.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil {
			finding.HTTPEvidence = &evidence
		}
		finding.CVEMatches, err = s.ListCVEMatchesByFinding(ctx, finding.ID)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) GetHTTPEvidence(ctx context.Context, findingID string) (models.HTTPEvidence, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT finding_id, request_raw, response_raw, status_code, response_time
FROM http_evidence
WHERE finding_id = ?
ORDER BY rowid ASC
LIMIT 1`, findingID)
	return scanHTTPEvidence(row)
}

func (s *Store) ListCVEMatchesByFinding(ctx context.Context, findingID string) ([]models.CVEMatch, error) {
	return s.listCVEMatches(ctx, `finding_id = ?`, findingID)
}

func (s *Store) ListCVEMatchesByTechnology(ctx context.Context, technologyID string) ([]models.CVEMatch, error) {
	return s.listCVEMatches(ctx, `technology_id = ?`, technologyID)
}

func (s *Store) ListCVEMatchesBySession(ctx context.Context, sessionID string) ([]models.CVEMatch, error) {
	return s.listCVEMatches(ctx, `
(session_id = ?
 OR finding_id IN (SELECT id FROM findings WHERE session_id = ?)
 OR technology_id IN (
	SELECT technologies.id
	FROM technologies
	JOIN targets ON targets.id = technologies.target_id
	WHERE targets.session_id = ?
))`, sessionID, sessionID, sessionID)
}

func (s *Store) listCVEMatches(ctx context.Context, where string, args ...any) ([]models.CVEMatch, error) {
	// #nosec G202 -- where is built by internal callers from fixed clauses; values are bound through placeholders.
	query := `
SELECT id, session_id, COALESCE(finding_id, ''), COALESCE(technology_id, ''), cve_id,
       cvss_v3_score, cvss_v3_vector, description, package_name, package_version, affected_version,
       fixed_version, patch_available, exploit_available, "references",
       source, confidence_score
FROM cve_matches
WHERE ` + where + `
ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []models.CVEMatch
	for rows.Next() {
		match, err := scanCVEMatch(rows)
		if err != nil {
			return nil, err
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func (s *Store) ListAttackVectors(ctx context.Context, sessionID string) ([]models.AttackVector, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, title, description, narrative, owasp_category, severity,
       confidence, steps, prereq_finding_ids, llm_reviewed, llm_notes, created_at
FROM attack_vectors
WHERE session_id = ?
ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vectors []models.AttackVector
	for rows.Next() {
		vector, err := scanAttackVector(rows)
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, vector)
	}
	return vectors, rows.Err()
}

func (s *Store) InsertSourceFinding(ctx context.Context, finding models.SourceFinding) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO source_findings (
	id, session_id, kind, language, framework, file_path, line_number,
	value, method, context, notes, confirmed_by_dynamic, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID,
		finding.SessionID,
		string(finding.Kind),
		finding.Language,
		finding.Framework,
		finding.FilePath,
		finding.LineNumber,
		finding.Value,
		finding.Method,
		finding.Context,
		finding.Notes,
		finding.ConfirmedByDynamic,
		formatTime(finding.CreatedAt),
	)
	return err
}

func (s *Store) ListSourceFindings(ctx context.Context, sessionID string, filter SourceFindingFilter) ([]models.SourceFinding, error) {
	query := `
SELECT id, session_id, kind, language, framework, file_path, line_number,
       value, method, context, notes, confirmed_by_dynamic, created_at
FROM source_findings
WHERE session_id = ?`
	args := []any{sessionID}
	if strings.TrimSpace(filter.Kind) != "" {
		query += ` AND kind = ?`
		args = append(args, filter.Kind)
	}
	query += ` ORDER BY kind ASC, file_path ASC, line_number ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []models.SourceFinding
	for rows.Next() {
		finding, err := scanSourceFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) MarkSourceFindingConfirmed(ctx context.Context, sourceFindingID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE source_findings SET confirmed_by_dynamic = TRUE WHERE id = ?`, sourceFindingID)
	return err
}

func (s *Store) InsertAttackGraphEdge(ctx context.Context, edge models.AttackGraphEdge) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO attack_graph_edges (id, session_id, from_id, to_id, relation, confidence, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		edge.ID,
		edge.SessionID,
		edge.FromID,
		edge.ToID,
		string(edge.Relation),
		edge.Confidence,
		formatTime(edge.CreatedAt),
	)
	return err
}

func (s *Store) DeleteAttackGraphEdges(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM attack_graph_edges WHERE session_id = ?`, sessionID)
	return err
}

func (s *Store) ListAttackGraphEdges(ctx context.Context, sessionID string) ([]models.AttackGraphEdge, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, from_id, to_id, relation, confidence, created_at
FROM attack_graph_edges
WHERE session_id = ?
ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []models.AttackGraphEdge
	for rows.Next() {
		edge, err := scanAttackGraphEdge(rows)
		if err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func (s *Store) ListLLMAnalyses(ctx context.Context, sessionID string) ([]models.LLMAnalysis, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, model_id, prompt_summary, messages, total_tokens, created_at
FROM llm_analyses
WHERE session_id = ?
ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var analyses []models.LLMAnalysis
	for rows.Next() {
		analysis, err := scanLLMAnalysis(rows)
		if err != nil {
			return nil, err
		}
		analyses = append(analyses, analysis)
	}
	return analyses, rows.Err()
}

func (s *Store) ListPlugins(ctx context.Context) ([]models.PluginRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, binary, sha256, enabled, created_at, updated_at
FROM plugins
ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plugins []models.PluginRecord
	for rows.Next() {
		plugin, err := scanPlugin(rows)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, plugin)
	}
	return plugins, rows.Err()
}

func (s *Store) ListToolRuns(ctx context.Context, sessionID string) ([]models.ToolRun, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, COALESCE(target_id, ''), tool_id, args, stdout_path, stderr_path,
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
  (SELECT COUNT(*) FROM findings WHERE session_id = ? AND tool_id LIKE 'audit/%'),
  (SELECT COUNT(*) FROM findings WHERE session_id = ? AND tool_id NOT LIKE 'audit/%'),
  (SELECT COUNT(DISTINCT to_id) FROM attack_graph_edges WHERE session_id = ? AND relation = 'confirms'),
  (SELECT COUNT(*) FROM source_findings WHERE session_id = ?),
  (SELECT COUNT(*) FROM tool_runs WHERE session_id = ?)`,
		sessionID, sessionID, sessionID, sessionID, sessionID, sessionID, sessionID,
	).Scan(&stats.TargetCount, &stats.FindingCount, &stats.StaticFindingCount, &stats.DynamicFindingCount, &stats.ConfirmedByBoth, &stats.SourceFindingCount, &stats.ToolRunCount)
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
		if !entry.IsDir() || !validSessionID(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name(), "session.db")
		if _, err := os.Stat(path); err != nil {
			continue
		}
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
	sessionDir := filepath.Dir(path)
	if err := store.Close(); err != nil {
		return err
	}
	return os.RemoveAll(sessionDir)
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
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		var existing string
		err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, migration.version).Scan(&existing)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migration.body); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, migration.version, formatTime(time.Now().UTC())); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

type migrationFile struct {
	version string
	body    string
}

func loadMigrations() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var migrations []migrationFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".down.sql") {
			continue
		}
		body, err := migrationFS.ReadFile(path.Join("migrations", name))
		if err != nil {
			return nil, err
		}
		version := strings.TrimSuffix(name, ".sql")
		version = strings.TrimSuffix(version, ".up")
		migrations = append(migrations, migrationFile{version: version, body: string(body)})
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(row rowScanner) (models.Session, error) {
	var session models.Session
	var inScope, outOfScope, phases, tools, parameters, runnerOptions string
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
		&session.WorkloadMode,
		&session.SourcePath,
		&tools,
		&parameters,
		&runnerOptions,
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
	session.WorkloadMode = firstWorkloadMode(session.WorkloadMode)
	if err := json.Unmarshal([]byte(inScope), &session.InScope); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(outOfScope), &session.OutOfScope); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(phases), &session.EnabledPhases); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(firstJSON(tools, "[]")), &session.EnabledTools); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(firstJSON(parameters, "{}")), &session.ToolParameters); err != nil {
		return models.Session{}, err
	}
	if err := json.Unmarshal([]byte(firstJSON(runnerOptions, "{}")), &session.RunnerOptions); err != nil {
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

func scanTechnology(row rowScanner) (models.Technology, error) {
	var technology models.Technology
	err := row.Scan(
		&technology.ID,
		&technology.TargetID,
		&technology.Name,
		&technology.Version,
		&technology.Category,
		&technology.Confidence,
		&technology.SourceTool,
	)
	if err != nil {
		return models.Technology{}, err
	}
	return technology, nil
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
		&finding.CodeContext,
		&finding.FlowSummary,
		&finding.Status,
		&finding.Notes,
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

func scanHTTPEvidence(row rowScanner) (models.HTTPEvidence, error) {
	var evidence models.HTTPEvidence
	err := row.Scan(
		&evidence.FindingID,
		&evidence.RequestRaw,
		&evidence.ResponseRaw,
		&evidence.StatusCode,
		&evidence.ResponseTime,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.HTTPEvidence{}, ErrNotFound
		}
		return models.HTTPEvidence{}, err
	}
	return evidence, nil
}

func scanCVEMatch(row rowScanner) (models.CVEMatch, error) {
	var match models.CVEMatch
	var references string
	err := row.Scan(
		&match.ID,
		&match.SessionID,
		&match.FindingID,
		&match.TechnologyID,
		&match.CVEID,
		&match.CVSSv3Score,
		&match.CVSSv3Vector,
		&match.Description,
		&match.PackageName,
		&match.PackageVersion,
		&match.AffectedVersion,
		&match.FixedVersion,
		&match.PatchAvailable,
		&match.ExploitAvailable,
		&references,
		&match.Source,
		&match.ConfidenceScore,
	)
	if err != nil {
		return models.CVEMatch{}, err
	}
	if err := json.Unmarshal([]byte(references), &match.References); err != nil {
		return models.CVEMatch{}, err
	}
	return match, nil
}

func scanSourceFinding(row rowScanner) (models.SourceFinding, error) {
	var finding models.SourceFinding
	var createdAt string
	err := row.Scan(
		&finding.ID,
		&finding.SessionID,
		&finding.Kind,
		&finding.Language,
		&finding.Framework,
		&finding.FilePath,
		&finding.LineNumber,
		&finding.Value,
		&finding.Method,
		&finding.Context,
		&finding.Notes,
		&finding.ConfirmedByDynamic,
		&createdAt,
	)
	if err != nil {
		return models.SourceFinding{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.SourceFinding{}, err
	}
	finding.CreatedAt = created
	return finding, nil
}

func scanAttackGraphEdge(row rowScanner) (models.AttackGraphEdge, error) {
	var edge models.AttackGraphEdge
	var createdAt string
	err := row.Scan(
		&edge.ID,
		&edge.SessionID,
		&edge.FromID,
		&edge.ToID,
		&edge.Relation,
		&edge.Confidence,
		&createdAt,
	)
	if err != nil {
		return models.AttackGraphEdge{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.AttackGraphEdge{}, err
	}
	edge.CreatedAt = created
	return edge, nil
}

func scanAttackVector(row rowScanner) (models.AttackVector, error) {
	var vector models.AttackVector
	var steps, prereqs, createdAt string
	err := row.Scan(
		&vector.ID,
		&vector.SessionID,
		&vector.Title,
		&vector.Description,
		&vector.Narrative,
		&vector.OWASPCategory,
		&vector.Severity,
		&vector.Confidence,
		&steps,
		&prereqs,
		&vector.LLMReviewed,
		&vector.LLMNotes,
		&createdAt,
	)
	if err != nil {
		return models.AttackVector{}, err
	}
	if err := json.Unmarshal([]byte(steps), &vector.Steps); err != nil {
		return models.AttackVector{}, err
	}
	if err := json.Unmarshal([]byte(prereqs), &vector.PrereqFindingIDs); err != nil {
		return models.AttackVector{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.AttackVector{}, err
	}
	vector.CreatedAt = created
	return vector, nil
}

func scanLLMAnalysis(row rowScanner) (models.LLMAnalysis, error) {
	var analysis models.LLMAnalysis
	var messages, createdAt string
	err := row.Scan(
		&analysis.ID,
		&analysis.SessionID,
		&analysis.ModelID,
		&analysis.PromptSummary,
		&messages,
		&analysis.TotalTokens,
		&createdAt,
	)
	if err != nil {
		return models.LLMAnalysis{}, err
	}
	if err := json.Unmarshal([]byte(messages), &analysis.Messages); err != nil {
		return models.LLMAnalysis{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.LLMAnalysis{}, err
	}
	analysis.CreatedAt = created
	return analysis, nil
}

func scanPlugin(row rowScanner) (models.PluginRecord, error) {
	var plugin models.PluginRecord
	var createdAt, updatedAt string
	err := row.Scan(
		&plugin.ID,
		&plugin.Name,
		&plugin.Binary,
		&plugin.SHA256,
		&plugin.Enabled,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return models.PluginRecord{}, err
	}
	created, err := parseTime(createdAt)
	if err != nil {
		return models.PluginRecord{}, err
	}
	updated, err := parseTime(updatedAt)
	if err != nil {
		return models.PluginRecord{}, err
	}
	plugin.CreatedAt = created
	plugin.UpdatedAt = updated
	return plugin, nil
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
		&run.StdoutPath,
		&run.StderrPath,
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

func firstJSON(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstWorkloadMode(mode models.WorkloadMode) models.WorkloadMode {
	switch mode {
	case models.WorkloadModeStatic, models.WorkloadModeCombined:
		return mode
	default:
		return models.WorkloadModeDynamic
	}
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

func pathInsideOrEqual(root, candidate string) bool {
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}
