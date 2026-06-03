package models

import "time"

type PluginRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Binary      string    `json:"binary"`
	SHA256      string    `json:"sha256,omitempty"`
	Phase       string    `json:"phase"`
	Description string    `json:"description"`
	HomepageURL string    `json:"homepage_url"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
