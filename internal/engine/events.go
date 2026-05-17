package engine

import "time"

type ScanEventType string

const (
	ScanEventQueued         ScanEventType = "queued"
	ScanEventRunning        ScanEventType = "running"
	ScanEventToolStarted    ScanEventType = "tool_started"
	ScanEventToolCompleted  ScanEventType = "tool_completed"
	ScanEventToolError      ScanEventType = "tool_error"
	ScanEventPhaseStarted   ScanEventType = "phase_started"
	ScanEventPhaseCompleted ScanEventType = "phase_completed"
	ScanEventFindingFound   ScanEventType = "finding_found"
	ScanEventAuthStatus     ScanEventType = "auth_status"
	ScanEventFailed         ScanEventType = "failed"
	ScanEventCompleted      ScanEventType = "completed"
	ScanEventCancelled      ScanEventType = "cancelled"
)

type ScanEvent struct {
	Type         ScanEventType `json:"type"`
	SessionID    string        `json:"session_id"`
	TargetID     string        `json:"target_id,omitempty"`
	ToolID       string        `json:"tool_id,omitempty"`
	Phase        string        `json:"phase,omitempty"`
	FindingID    string        `json:"finding_id,omitempty"`
	FindingTitle string        `json:"finding_title,omitempty"`
	Severity     string        `json:"severity,omitempty"`
	Status       string        `json:"status,omitempty"`
	Message      string        `json:"message,omitempty"`
	FindingCount int           `json:"finding_count,omitempty"`
	DurationMS   int64         `json:"duration_ms,omitempty"`
	At           time.Time     `json:"at"`
}

type ScanEventHandler func(ScanEvent)
