package models

import "time"

type MonitorStatus string

const (
	MonitorRunStatusRunning   MonitorStatus = "running"
	MonitorRunStatusCompleted MonitorStatus = "completed"
	MonitorRunStatusFailed    MonitorStatus = "failed"
)

type SurfaceChangeType string

const (
	SurfaceChangeNewHost         SurfaceChangeType = "new_host"
	SurfaceChangeResolvedHost    SurfaceChangeType = "resolved_host"
	SurfaceChangeNewService      SurfaceChangeType = "new_service"
	SurfaceChangeResolvedService SurfaceChangeType = "resolved_service"
	SurfaceChangeServiceChanged  SurfaceChangeType = "service_changed"
	SurfaceChangeNewTechnology   SurfaceChangeType = "new_technology"
	SurfaceChangeEndpointChanged SurfaceChangeType = "endpoint_changed"
	SurfaceChangeNewFinding      SurfaceChangeType = "new_finding"
	SurfaceChangeSeverityChanged SurfaceChangeType = "finding_severity_changed"
	SurfaceChangeResolvedFinding SurfaceChangeType = "resolved_finding"
)

type MonitorNotificationConfig struct {
	SlackWebhookURL   string `json:"slack_webhook_url,omitempty"`
	DiscordWebhookURL string `json:"discord_webhook_url,omitempty"`
	Email             string `json:"email,omitempty"`
}

func (c MonitorNotificationConfig) Redacted() MonitorNotificationConfig {
	if c.SlackWebhookURL != "" {
		c.SlackWebhookURL = "********"
	}
	if c.DiscordWebhookURL != "" {
		c.DiscordWebhookURL = "********"
	}
	return c
}

type MonitorConfig struct {
	ID                 string                    `json:"id"`
	Name               string                    `json:"name"`
	TargetInput        string                    `json:"target_input"`
	InScope            []string                  `json:"in_scope"`
	OutOfScope         []string                  `json:"out_of_scope"`
	Schedule           string                    `json:"schedule"`
	EnabledPhases      []string                  `json:"enabled_phases"`
	EnabledTools       []string                  `json:"enabled_tools"`
	ToolParameters     map[string]map[string]any `json:"tool_parameters,omitempty"`
	RunnerOptions      ScanRunnerOptions         `json:"runner_options,omitempty"`
	AlertOn            []string                  `json:"alert_on"`
	NotificationConfig MonitorNotificationConfig `json:"notification_config,omitempty"`
	BaselineSessionID  string                    `json:"baseline_session_id,omitempty"`
	LastRunAt          *time.Time                `json:"last_run_at,omitempty"`
	NextRunAt          *time.Time                `json:"next_run_at,omitempty"`
	Enabled            bool                      `json:"enabled"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
}

func (c MonitorConfig) Redacted() MonitorConfig {
	c.NotificationConfig = c.NotificationConfig.Redacted()
	return c
}

type MonitorRun struct {
	ID           string        `json:"id"`
	ConfigID     string        `json:"config_id"`
	SessionID    string        `json:"session_id,omitempty"`
	Status       MonitorStatus `json:"status"`
	ChangesFound bool          `json:"changes_found"`
	Error        string        `json:"error,omitempty"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  *time.Time    `json:"completed_at,omitempty"`
}

type SurfaceChange struct {
	ID            string            `json:"id"`
	MonitorRunID  string            `json:"monitor_run_id"`
	SessionID     string            `json:"session_id"`
	ChangeType    SurfaceChangeType `json:"change_type"`
	Severity      Severity          `json:"severity"`
	Description   string            `json:"description"`
	PreviousValue string            `json:"previous_value,omitempty"`
	CurrentValue  string            `json:"current_value,omitempty"`
	TargetID      string            `json:"target_id,omitempty"`
	FindingID     string            `json:"finding_id,omitempty"`
	Alerted       bool              `json:"alerted"`
	CreatedAt     time.Time         `json:"created_at"`
}
