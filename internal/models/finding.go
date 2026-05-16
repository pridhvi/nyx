package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type FindingType string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeExposure         FindingType = "exposure"
	FindingTypeInfo             FindingType = "info"
)

type Finding struct {
	ID                 string        `json:"id"`
	SessionID          string        `json:"session_id"`
	TargetID           string        `json:"target_id"`
	ToolID             string        `json:"tool_id"`
	Type               FindingType   `json:"type"`
	Severity           Severity      `json:"severity"`
	Confidence         float64       `json:"confidence"`
	CVSSScore          float64       `json:"cvss_score"`
	Title              string        `json:"title"`
	Description        string        `json:"description"`
	Remediation        string        `json:"remediation"`
	URL                string        `json:"url"`
	Parameter          string        `json:"parameter,omitempty"`
	Method             string        `json:"method,omitempty"`
	EvidenceRaw        string        `json:"evidence_raw"`
	EvidenceNormalized string        `json:"evidence_normalized"`
	CodeContext        string        `json:"code_context,omitempty"`
	FlowSummary        string        `json:"flow_summary,omitempty"`
	Status             string        `json:"status,omitempty"`
	Notes              string        `json:"notes,omitempty"`
	HTTPEvidence       *HTTPEvidence `json:"http_evidence,omitempty"`
	Tags               []string      `json:"tags"`
	CVEMatches         []CVEMatch    `json:"cve_matches,omitempty"`
	CreatedAt          time.Time     `json:"created_at"`
}

type HTTPEvidence struct {
	FindingID    string `json:"finding_id"`
	RequestRaw   string `json:"request_raw"`
	ResponseRaw  string `json:"response_raw"`
	StatusCode   int    `json:"status_code"`
	ResponseTime int64  `json:"response_time_ms"`
}
