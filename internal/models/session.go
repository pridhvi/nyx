package models

import (
	"encoding/json"
	"strings"
	"time"
)

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

const SessionScanOptionsKey = "_scan"

type sessionJSON Session

func (s Session) MarshalJSON() ([]byte, error) {
	copy := sessionJSON(s)
	copy.ToolParameters = RedactedToolParameters(s.ToolParameters)
	return json.Marshal(copy)
}

func RedactedToolParameters(input map[string]map[string]any) map[string]map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]map[string]any, len(input))
	for toolID, params := range input {
		copied := make(map[string]any, len(params))
		for key, value := range params {
			if toolID == SessionScanOptionsKey && scanOptionSecret(key) {
				copied[key] = "********"
				continue
			}
			copied[key] = value
		}
		out[toolID] = copied
	}
	return out
}

func scanOptionSecret(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(normalized, "header") ||
		strings.Contains(normalized, "cookie") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret")
}

func BuildScanToolParameters(existing map[string]map[string]any, routeSeeds []string, routeSeedFile string, headers, cookies map[string]string, cookieHeader string) map[string]map[string]any {
	if existing == nil {
		existing = map[string]map[string]any{}
	}
	scan := map[string]any{}
	if current := existing[SessionScanOptionsKey]; current != nil {
		for key, value := range current {
			scan[key] = value
		}
	}
	if len(routeSeeds) > 0 {
		scan["route_seeds"] = routeSeeds
	}
	if strings.TrimSpace(routeSeedFile) != "" {
		scan["route_seed_file"] = strings.TrimSpace(routeSeedFile)
	}
	if len(headers) > 0 {
		scan["auth_headers"] = headers
	}
	if len(cookies) > 0 {
		scan["auth_cookies"] = cookies
	}
	if strings.TrimSpace(cookieHeader) != "" {
		scan["auth_cookie_header"] = strings.TrimSpace(cookieHeader)
	}
	if len(scan) > 0 {
		existing[SessionScanOptionsKey] = scan
	}
	return existing
}

type ScanRunnerOptions struct {
	Concurrency        int    `json:"concurrency,omitempty"`
	PerToolConcurrency int    `json:"per_tool_concurrency,omitempty"`
	ToolTimeoutSeconds int    `json:"tool_timeout_seconds,omitempty"`
	ToolDelayMS        int    `json:"tool_delay_ms,omitempty"`
	RateLimit          string `json:"rate_limit,omitempty"`
	EvasionProfile     string `json:"evasion_profile,omitempty"`
	JitterMS           int    `json:"jitter_ms,omitempty"`
	ProxyURL           string `json:"proxy_url,omitempty"`
	UserAgentProfile   string `json:"user_agent_profile,omitempty"`
	HeaderProfile      string `json:"header_profile,omitempty"`
	AdaptiveBackoff    bool   `json:"adaptive_backoff,omitempty"`
	MaxBackoffSeconds  int    `json:"max_backoff_seconds,omitempty"`
}
