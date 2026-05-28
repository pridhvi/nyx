package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type PayloadFilter struct {
	Type      string
	Validated *bool
}

type CredentialFilter struct {
	Valid   *bool
	Type    string
	Service string
}

type OSINTFilter struct {
	Kind   string
	Source string
}

type ProviderStatusFilter struct {
	Provider string
	Module   string
	Status   string
}

type PowerCallbackFilter struct {
	FindingID string
	Provider  string
	Received  *bool
}

func (s *Store) GetFinding(ctx context.Context, sessionID, findingID string) (models.Finding, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, session_id, COALESCE(target_id, ''), tool_id, type, severity, confidence, cvss_score,
       title, description, remediation, url, parameter, method, evidence_raw,
       evidence_normalized, code_context, flow_summary, status, notes, tags, created_at
FROM findings
WHERE session_id = ? AND id = ?`, sessionID, findingID)
	finding, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Finding{}, ErrNotFound
	}
	if err != nil {
		return models.Finding{}, err
	}
	return finding, nil
}

func (s *Store) InsertProviderStatus(ctx context.Context, status models.ProviderStatus) error {
	metadata, err := json.Marshal(status.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO provider_statuses (id, session_id, provider, module, status, message, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		status.ID, status.SessionID, status.Provider, status.Module, status.Status,
		status.Message, string(metadata), formatTime(status.CreatedAt))
	return err
}

func (s *Store) ListProviderStatuses(ctx context.Context, sessionID string, filter ProviderStatusFilter) ([]models.ProviderStatus, error) {
	query := `SELECT id, session_id, provider, module, status, message, metadata, created_at FROM provider_statuses WHERE session_id = ?`
	args := []any{sessionID}
	if filter.Provider != "" {
		query += ` AND provider = ?`
		args = append(args, filter.Provider)
	}
	if filter.Module != "" {
		query += ` AND module = ?`
		args = append(args, filter.Module)
	}
	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, filter.Status)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var statuses []models.ProviderStatus
	for rows.Next() {
		status, err := scanProviderStatus(rows)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, rows.Err()
}

func (s *Store) InsertPowerCallback(ctx context.Context, callback models.PowerCallback) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO power_callbacks (
	id, session_id, finding_id, provider, token, url, source_ip, raw_event,
	received, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		callback.ID, callback.SessionID, nullableString(callback.FindingID), callback.Provider,
		callback.Token, callback.URL, callback.SourceIP, callback.RawEvent, callback.Received,
		formatTime(callback.CreatedAt), formatTime(callback.UpdatedAt))
	return err
}

func (s *Store) MarkPowerCallbackReceived(ctx context.Context, sessionID, token, sourceIP, rawEvent string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE power_callbacks
SET received = 1, source_ip = ?, raw_event = ?, updated_at = ?
WHERE session_id = ? AND token = ?`,
		sourceIP, rawEvent, formatTime(time.Now().UTC()), sessionID, token)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func (s *Store) ListPowerCallbacks(ctx context.Context, sessionID string, filter PowerCallbackFilter) ([]models.PowerCallback, error) {
	query := `SELECT id, session_id, COALESCE(finding_id, ''), provider, token, url, source_ip, raw_event, received, created_at, updated_at FROM power_callbacks WHERE session_id = ?`
	args := []any{sessionID}
	if filter.FindingID != "" {
		query += ` AND finding_id = ?`
		args = append(args, filter.FindingID)
	}
	if filter.Provider != "" {
		query += ` AND provider = ?`
		args = append(args, filter.Provider)
	}
	if filter.Received != nil {
		query += ` AND received = ?`
		args = append(args, *filter.Received)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var callbacks []models.PowerCallback
	for rows.Next() {
		callback, err := scanPowerCallback(rows)
		if err != nil {
			return nil, err
		}
		callbacks = append(callbacks, callback)
	}
	return callbacks, rows.Err()
}

func (s *Store) InsertPayload(ctx context.Context, payload models.Payload) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO payloads (
	id, finding_id, session_id, payload_type, payload, context, target_waf,
	target_db, bypass_technique, confidence, validated, validated_response,
	rank, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payload.ID, payload.FindingID, payload.SessionID, payload.PayloadType, payload.Payload,
		payload.Context, payload.TargetWAF, payload.TargetDB, payload.BypassTechnique,
		payload.Confidence, payload.Validated, payload.ValidatedResponse, payload.Rank,
		formatTime(payload.CreatedAt))
	return err
}

func (s *Store) DeletePayloadsByFinding(ctx context.Context, sessionID, findingID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM payloads WHERE session_id = ? AND finding_id = ?`, sessionID, findingID)
	return err
}

func (s *Store) ListPayloadsByFinding(ctx context.Context, sessionID, findingID string) ([]models.Payload, error) {
	return s.listPayloads(ctx, `session_id = ? AND finding_id = ?`, sessionID, findingID)
}

func (s *Store) ListPayloadsBySession(ctx context.Context, sessionID string, filter PayloadFilter) ([]models.Payload, error) {
	where := `session_id = ?`
	args := []any{sessionID}
	if strings.TrimSpace(filter.Type) != "" {
		where += ` AND payload_type = ?`
		args = append(args, filter.Type)
	}
	if filter.Validated != nil {
		where += ` AND validated = ?`
		args = append(args, *filter.Validated)
	}
	return s.listPayloads(ctx, where, args...)
}

func (s *Store) PayloadByID(ctx context.Context, sessionID, payloadID string) (models.Payload, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, finding_id, session_id, payload_type, payload, context, target_waf,
       target_db, bypass_technique, confidence, validated, validated_response,
       rank, created_at
FROM payloads
WHERE session_id = ? AND id = ?`, sessionID, payloadID)
	if err != nil {
		return models.Payload{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return models.Payload{}, ErrNotFound
	}
	return scanPayload(rows)
}

func (s *Store) listPayloads(ctx context.Context, where string, args ...any) ([]models.Payload, error) {
	// #nosec G202 -- where is built by internal callers from fixed clauses; values are bound through placeholders.
	rows, err := s.db.QueryContext(ctx, `
SELECT id, finding_id, session_id, payload_type, payload, context, target_waf,
       target_db, bypass_technique, confidence, validated, validated_response,
       rank, created_at
FROM payloads
WHERE `+where+`
ORDER BY rank ASC, created_at ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var payloads []models.Payload
	for rows.Next() {
		payload, err := scanPayload(rows)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}
	return payloads, rows.Err()
}

func (s *Store) UpdatePayloadValidation(ctx context.Context, sessionID, payloadID, response string, validated bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE payloads SET validated = ?, validated_response = ? WHERE session_id = ? AND id = ?`, validated, response, sessionID, payloadID)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func (s *Store) InsertCredentialFinding(ctx context.Context, credential models.CredentialFinding) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO credential_findings (
	id, session_id, target_id, finding_id, credential_type, username, password,
	service, url, valid, lockout_detected, evidence, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		credential.ID, credential.SessionID, nullableString(credential.TargetID), nullableString(credential.FindingID),
		credential.CredentialType, credential.Username, credential.Password, credential.Service, credential.URL,
		credential.Valid, credential.LockoutDetected, credential.Evidence, formatTime(credential.CreatedAt))
	return err
}

func (s *Store) ListCredentialFindings(ctx context.Context, sessionID string, filter CredentialFilter) ([]models.CredentialFinding, error) {
	query := `
SELECT id, session_id, COALESCE(target_id, ''), COALESCE(finding_id, ''), credential_type,
       username, password, service, url, valid, lockout_detected, evidence, created_at
FROM credential_findings
WHERE session_id = ?`
	args := []any{sessionID}
	if filter.Valid != nil {
		query += ` AND valid = ?`
		args = append(args, *filter.Valid)
	}
	if filter.Type != "" {
		query += ` AND credential_type = ?`
		args = append(args, filter.Type)
	}
	if filter.Service != "" {
		query += ` AND service = ?`
		args = append(args, filter.Service)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var credentials []models.CredentialFinding
	for rows.Next() {
		credential, err := scanCredentialFinding(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *Store) CredentialFindingByID(ctx context.Context, sessionID, id string) (models.CredentialFinding, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, session_id, COALESCE(target_id, ''), COALESCE(finding_id, ''), credential_type,
       username, password, service, url, valid, lockout_detected, evidence, created_at
FROM credential_findings
WHERE session_id = ? AND id = ?`, sessionID, id)
	if err != nil {
		return models.CredentialFinding{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return models.CredentialFinding{}, ErrNotFound
	}
	return scanCredentialFinding(rows)
}

func (s *Store) UpdateCredentialFinding(ctx context.Context, credential models.CredentialFinding) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE credential_findings
SET valid = ?, lockout_detected = ?, evidence = ?, password = ?
WHERE session_id = ? AND id = ?`,
		credential.Valid, credential.LockoutDetected, credential.Evidence, credential.Password, credential.SessionID, credential.ID)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func (s *Store) InsertOSINTFinding(ctx context.Context, finding models.OSINTFinding) error {
	metadata, err := json.Marshal(finding.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO osint_findings (id, session_id, kind, value, source, confidence, target_id, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		finding.ID, finding.SessionID, finding.Kind, finding.Value, finding.Source,
		finding.Confidence, nullableString(finding.TargetID), string(metadata), formatTime(finding.CreatedAt))
	return err
}

func (s *Store) ListOSINTFindings(ctx context.Context, sessionID string, filter OSINTFilter) ([]models.OSINTFinding, error) {
	query := `SELECT id, session_id, kind, value, source, confidence, COALESCE(target_id, ''), metadata, created_at FROM osint_findings WHERE session_id = ?`
	args := []any{sessionID}
	if filter.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, filter.Kind)
	}
	if filter.Source != "" {
		query += ` AND source = ?`
		args = append(args, filter.Source)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []models.OSINTFinding
	for rows.Next() {
		finding, err := scanOSINTFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (s *Store) OSINTFindingByID(ctx context.Context, sessionID, id string) (models.OSINTFinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_id, kind, value, source, confidence, COALESCE(target_id, ''), metadata, created_at FROM osint_findings WHERE session_id = ? AND id = ?`, sessionID, id)
	if err != nil {
		return models.OSINTFinding{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return models.OSINTFinding{}, ErrNotFound
	}
	return scanOSINTFinding(rows)
}

func (s *Store) InsertADEntity(ctx context.Context, entity models.ADEntity) error {
	metadata, err := json.Marshal(entity.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO ad_entities (id, session_id, entity_type, name, domain, sid, distinguished_name, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entity.ID, entity.SessionID, entity.EntityType, entity.Name, entity.Domain, entity.SID,
		entity.DistinguishedName, string(metadata), formatTime(entity.CreatedAt))
	return err
}

func (s *Store) ListADEntities(ctx context.Context, sessionID, entityType string) ([]models.ADEntity, error) {
	query := `SELECT id, session_id, entity_type, name, domain, sid, distinguished_name, metadata, created_at FROM ad_entities WHERE session_id = ?`
	args := []any{sessionID}
	if entityType != "" {
		query += ` AND entity_type = ?`
		args = append(args, entityType)
	}
	query += ` ORDER BY entity_type ASC, name ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entities []models.ADEntity
	for rows.Next() {
		entity, err := scanADEntity(rows)
		if err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}
	return entities, rows.Err()
}

func (s *Store) InsertADRelationship(ctx context.Context, relationship models.ADRelationship) error {
	metadata, err := json.Marshal(relationship.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO ad_relationships (id, session_id, from_entity_id, to_entity_id, relation, metadata, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		relationship.ID, relationship.SessionID, relationship.FromEntityID, relationship.ToEntityID,
		relationship.Relation, string(metadata), formatTime(relationship.CreatedAt))
	return err
}

func (s *Store) ListADRelationships(ctx context.Context, sessionID string) ([]models.ADRelationship, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_id, from_entity_id, to_entity_id, relation, metadata, created_at FROM ad_relationships WHERE session_id = ? ORDER BY created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var relationships []models.ADRelationship
	for rows.Next() {
		relationship, err := scanADRelationship(rows)
		if err != nil {
			return nil, err
		}
		relationships = append(relationships, relationship)
	}
	return relationships, rows.Err()
}

func (s *Store) InsertADArtifact(ctx context.Context, artifact models.ADArtifact) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ad_artifacts (id, session_id, artifact_type, path, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		artifact.ID, artifact.SessionID, artifact.ArtifactType, artifact.Path, artifact.Summary, formatTime(artifact.CreatedAt))
	return err
}

func (s *Store) ListADArtifacts(ctx context.Context, sessionID string) ([]models.ADArtifact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_id, artifact_type, path, summary, created_at FROM ad_artifacts WHERE session_id = ? ORDER BY created_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var artifacts []models.ADArtifact
	for rows.Next() {
		artifact, err := scanADArtifact(rows)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, rows.Err()
}

func (s *Store) InsertBlockEvent(ctx context.Context, event models.BlockEvent) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO block_events (id, session_id, target_id, tool_id, url, status_code, signal, response_snippet, backoff_ms, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.SessionID, nullableString(event.TargetID), event.ToolID, event.URL,
		event.StatusCode, event.Signal, event.ResponseSnippet, event.BackoffMS, formatTime(event.CreatedAt))
	return err
}

func (s *Store) ListBlockEvents(ctx context.Context, sessionID string) ([]models.BlockEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_id, COALESCE(target_id, ''), tool_id, url, status_code, signal, response_snippet, backoff_ms, created_at FROM block_events WHERE session_id = ? ORDER BY created_at DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []models.BlockEvent
	for rows.Next() {
		event, err := scanBlockEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) InsertPoCResult(ctx context.Context, result models.PoCResult) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO poc_results (
	id, session_id, finding_id, target_id, poc_type, status, payload_id, request_raw,
	response_raw, response_code, response_time_ms, evidence, canary_token,
	callback_received, impact_narrative, created_at, completed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ID, result.SessionID, result.FindingID, nullableString(result.TargetID), result.PoCType,
		string(result.Status), nullableString(result.PayloadID), result.RequestRaw, result.ResponseRaw,
		result.ResponseCode, result.ResponseTimeMS, result.Evidence, result.CanaryToken,
		result.CallbackReceived, result.ImpactNarrative, formatTime(result.CreatedAt), formatTimePtr(result.CompletedAt))
	return err
}

func (s *Store) UpdatePoCResult(ctx context.Context, result models.PoCResult) error {
	update, err := s.db.ExecContext(ctx, `
UPDATE poc_results
SET status = ?, request_raw = ?, response_raw = ?, response_code = ?, response_time_ms = ?,
    evidence = ?, callback_received = ?, impact_narrative = ?, completed_at = ?
WHERE session_id = ? AND id = ?`,
		string(result.Status), result.RequestRaw, result.ResponseRaw, result.ResponseCode,
		result.ResponseTimeMS, result.Evidence, result.CallbackReceived, result.ImpactNarrative,
		formatTimePtr(result.CompletedAt), result.SessionID, result.ID)
	if err != nil {
		return err
	}
	return requireAffected(update)
}

func (s *Store) ListPoCResults(ctx context.Context, sessionID, findingID string) ([]models.PoCResult, error) {
	query := `
SELECT id, session_id, finding_id, COALESCE(target_id, ''), poc_type, status,
       COALESCE(payload_id, ''), request_raw, response_raw, response_code,
       response_time_ms, evidence, canary_token, callback_received,
       impact_narrative, created_at, completed_at
FROM poc_results
WHERE session_id = ?`
	args := []any{sessionID}
	if findingID != "" {
		query += ` AND finding_id = ?`
		args = append(args, findingID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []models.PoCResult
	for rows.Next() {
		result, err := scanPoCResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

func scanProviderStatus(row rowScanner) (models.ProviderStatus, error) {
	var status models.ProviderStatus
	var metadata, createdAt string
	err := row.Scan(&status.ID, &status.SessionID, &status.Provider, &status.Module,
		&status.Status, &status.Message, &metadata, &createdAt)
	if err != nil {
		return models.ProviderStatus{}, err
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &status.Metadata); err != nil {
			return models.ProviderStatus{}, err
		}
	}
	status.CreatedAt, err = parseTime(createdAt)
	return status, err
}

func scanPowerCallback(row rowScanner) (models.PowerCallback, error) {
	var callback models.PowerCallback
	var createdAt, updatedAt string
	err := row.Scan(&callback.ID, &callback.SessionID, &callback.FindingID, &callback.Provider,
		&callback.Token, &callback.URL, &callback.SourceIP, &callback.RawEvent, &callback.Received,
		&createdAt, &updatedAt)
	if err != nil {
		return models.PowerCallback{}, err
	}
	callback.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return models.PowerCallback{}, err
	}
	callback.UpdatedAt, err = parseTime(updatedAt)
	return callback, err
}

func scanPayload(row rowScanner) (models.Payload, error) {
	var payload models.Payload
	var createdAt string
	err := row.Scan(&payload.ID, &payload.FindingID, &payload.SessionID, &payload.PayloadType,
		&payload.Payload, &payload.Context, &payload.TargetWAF, &payload.TargetDB,
		&payload.BypassTechnique, &payload.Confidence, &payload.Validated,
		&payload.ValidatedResponse, &payload.Rank, &createdAt)
	if err != nil {
		return models.Payload{}, err
	}
	payload.CreatedAt, err = parseTime(createdAt)
	return payload, err
}

func scanCredentialFinding(row rowScanner) (models.CredentialFinding, error) {
	var credential models.CredentialFinding
	var createdAt string
	err := row.Scan(&credential.ID, &credential.SessionID, &credential.TargetID, &credential.FindingID,
		&credential.CredentialType, &credential.Username, &credential.Password, &credential.Service,
		&credential.URL, &credential.Valid, &credential.LockoutDetected, &credential.Evidence, &createdAt)
	if err != nil {
		return models.CredentialFinding{}, err
	}
	credential.CreatedAt, err = parseTime(createdAt)
	return credential, err
}

func scanOSINTFinding(row rowScanner) (models.OSINTFinding, error) {
	var finding models.OSINTFinding
	var metadata, createdAt string
	err := row.Scan(&finding.ID, &finding.SessionID, &finding.Kind, &finding.Value, &finding.Source,
		&finding.Confidence, &finding.TargetID, &metadata, &createdAt)
	if err != nil {
		return models.OSINTFinding{}, err
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &finding.Metadata); err != nil {
			return models.OSINTFinding{}, err
		}
	}
	finding.CreatedAt, err = parseTime(createdAt)
	return finding, err
}

func scanADEntity(row rowScanner) (models.ADEntity, error) {
	var entity models.ADEntity
	var metadata, createdAt string
	err := row.Scan(&entity.ID, &entity.SessionID, &entity.EntityType, &entity.Name, &entity.Domain,
		&entity.SID, &entity.DistinguishedName, &metadata, &createdAt)
	if err != nil {
		return models.ADEntity{}, err
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &entity.Metadata); err != nil {
			return models.ADEntity{}, err
		}
	}
	entity.CreatedAt, err = parseTime(createdAt)
	return entity, err
}

func scanADRelationship(row rowScanner) (models.ADRelationship, error) {
	var relationship models.ADRelationship
	var metadata, createdAt string
	err := row.Scan(&relationship.ID, &relationship.SessionID, &relationship.FromEntityID,
		&relationship.ToEntityID, &relationship.Relation, &metadata, &createdAt)
	if err != nil {
		return models.ADRelationship{}, err
	}
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &relationship.Metadata); err != nil {
			return models.ADRelationship{}, err
		}
	}
	relationship.CreatedAt, err = parseTime(createdAt)
	return relationship, err
}

func scanADArtifact(row rowScanner) (models.ADArtifact, error) {
	var artifact models.ADArtifact
	var createdAt string
	err := row.Scan(&artifact.ID, &artifact.SessionID, &artifact.ArtifactType, &artifact.Path, &artifact.Summary, &createdAt)
	if err != nil {
		return models.ADArtifact{}, err
	}
	artifact.CreatedAt, err = parseTime(createdAt)
	return artifact, err
}

func scanBlockEvent(row rowScanner) (models.BlockEvent, error) {
	var event models.BlockEvent
	var createdAt string
	err := row.Scan(&event.ID, &event.SessionID, &event.TargetID, &event.ToolID, &event.URL,
		&event.StatusCode, &event.Signal, &event.ResponseSnippet, &event.BackoffMS, &createdAt)
	if err != nil {
		return models.BlockEvent{}, err
	}
	event.CreatedAt, err = parseTime(createdAt)
	return event, err
}

func scanPoCResult(row rowScanner) (models.PoCResult, error) {
	var result models.PoCResult
	var status, createdAt string
	var completed sql.NullString
	err := row.Scan(&result.ID, &result.SessionID, &result.FindingID, &result.TargetID,
		&result.PoCType, &status, &result.PayloadID, &result.RequestRaw, &result.ResponseRaw,
		&result.ResponseCode, &result.ResponseTimeMS, &result.Evidence, &result.CanaryToken,
		&result.CallbackReceived, &result.ImpactNarrative, &createdAt, &completed)
	if err != nil {
		return models.PoCResult{}, err
	}
	result.Status = models.PoCStatus(status)
	created, err := parseTime(createdAt)
	if err != nil {
		return models.PoCResult{}, err
	}
	result.CreatedAt = created
	if completed.Valid && completed.String != "" {
		parsed, err := parseTime(completed.String)
		if err != nil {
			return models.PoCResult{}, err
		}
		result.CompletedAt = &parsed
	}
	return result, nil
}

func requireAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func unsupportedAction(name string) error {
	return fmt.Errorf("%s is not configured for automatic execution in this safe slice", name)
}
