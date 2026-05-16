package models

import "time"

type SessionStatus string

const (
	SessionStatusPending   SessionStatus = "pending"
	SessionStatusRunning   SessionStatus = "running"
	SessionStatusPaused    SessionStatus = "paused"
	SessionStatusCompleted SessionStatus = "completed"
	SessionStatusFailed    SessionStatus = "failed"
	SessionStatusCancelled SessionStatus = "cancelled"
)

type ScanMode string

const (
	ScanModePassive ScanMode = "passive"
	ScanModeActive  ScanMode = "active"
	ScanModeStealth ScanMode = "stealth"
)

type WorkloadMode string

const (
	WorkloadModeDynamic  WorkloadMode = "dynamic"
	WorkloadModeStatic   WorkloadMode = "static"
	WorkloadModeCombined WorkloadMode = "combined"
)

type Session struct {
	ID             string                    `json:"id"`
	Name           string                    `json:"name"`
	Status         SessionStatus             `json:"status"`
	Mode           ScanMode                  `json:"mode"`
	WorkloadMode   WorkloadMode              `json:"workload_mode"`
	TargetInput    string                    `json:"target_input"`
	SourcePath     string                    `json:"source_path,omitempty"`
	InScope        []string                  `json:"in_scope"`
	OutOfScope     []string                  `json:"out_of_scope"`
	EnabledPhases  []string                  `json:"enabled_phases"`
	EnabledTools   []string                  `json:"enabled_tools"`
	ToolParameters map[string]map[string]any `json:"tool_parameters,omitempty"`
	RunnerOptions  ScanRunnerOptions         `json:"runner_options,omitempty"`
	LLMModel       string                    `json:"llm_model"`
	LLMBaseURL     string                    `json:"llm_base_url"`
	TargetCount    int                       `json:"target_count"`
	FindingCount   int                       `json:"finding_count"`
	StartedAt      *time.Time                `json:"started_at,omitempty"`
	CompletedAt    *time.Time                `json:"completed_at,omitempty"`
	CreatedAt      time.Time                 `json:"created_at"`
}

type ScanRunnerOptions struct {
	Concurrency        int    `json:"concurrency,omitempty"`
	PerToolConcurrency int    `json:"per_tool_concurrency,omitempty"`
	ToolTimeoutSeconds int    `json:"tool_timeout_seconds,omitempty"`
	ToolDelayMS        int    `json:"tool_delay_ms,omitempty"`
	RateLimit          string `json:"rate_limit,omitempty"`
}
