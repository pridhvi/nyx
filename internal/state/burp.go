package state

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func (s *Store) UpsertBurpConfig(ctx context.Context, config models.BurpConfig) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO burp_config (id, base_url, api_key, collaborator_provider, collaborator_url, interactsh_token, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	base_url = excluded.base_url,
	api_key = excluded.api_key,
	collaborator_provider = excluded.collaborator_provider,
	collaborator_url = excluded.collaborator_url,
	interactsh_token = excluded.interactsh_token,
	updated_at = excluded.updated_at`,
		config.ID, config.BaseURL, config.APIKey, config.CollaboratorProvider,
		config.CollaboratorURL, config.InteractshToken, formatTime(config.CreatedAt), formatTime(config.UpdatedAt))
	return err
}

func (s *Store) GetBurpConfig(ctx context.Context) (models.BurpConfig, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, base_url, api_key, collaborator_provider, collaborator_url, interactsh_token, created_at, updated_at
FROM burp_config
ORDER BY updated_at DESC
LIMIT 1`)
	var config models.BurpConfig
	var createdAt, updatedAt string
	err := row.Scan(&config.ID, &config.BaseURL, &config.APIKey, &config.CollaboratorProvider,
		&config.CollaboratorURL, &config.InteractshToken, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return models.BurpConfig{}, db.ErrNotFound
	}
	if err != nil {
		return models.BurpConfig{}, err
	}
	config.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return models.BurpConfig{}, err
	}
	config.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return config, err
}

func (s *Store) ListBurpCallbacks(ctx context.Context, sessionID string) ([]models.BurpCallback, error) {
	query := `SELECT id, provider, token, finding_id, session_id, source_ip, raw_event, created_at FROM burp_callbacks`
	args := []any{}
	if sessionID != "" {
		query += ` WHERE session_id = ?`
		args = append(args, sessionID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var callbacks []models.BurpCallback
	for rows.Next() {
		var callback models.BurpCallback
		var createdAt string
		if err := rows.Scan(&callback.ID, &callback.Provider, &callback.Token, &callback.FindingID,
			&callback.SessionID, &callback.SourceIP, &callback.RawEvent, &createdAt); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, err
		}
		callback.CreatedAt = parsed
		callbacks = append(callbacks, callback)
	}
	return callbacks, rows.Err()
}
