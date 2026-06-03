package models

import "time"

type Payload struct {
	ID                string    `json:"id"`
	FindingID         string    `json:"finding_id"`
	SessionID         string    `json:"session_id"`
	PayloadType       string    `json:"payload_type"`
	Payload           string    `json:"payload"`
	Context           string    `json:"context"`
	TargetWAF         string    `json:"target_waf"`
	TargetDB          string    `json:"target_db"`
	BypassTechnique   string    `json:"bypass_technique"`
	Confidence        float64   `json:"confidence"`
	Validated         bool      `json:"validated"`
	ValidatedResponse string    `json:"validated_response"`
	Rank              int       `json:"rank"`
	CreatedAt         time.Time `json:"created_at"`
}

type CredentialFinding struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	TargetID        string    `json:"target_id,omitempty"`
	FindingID       string    `json:"finding_id,omitempty"`
	CredentialType  string    `json:"credential_type"`
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	Service         string    `json:"service"`
	URL             string    `json:"url"`
	Valid           bool      `json:"valid"`
	LockoutDetected bool      `json:"lockout_detected"`
	Evidence        string    `json:"evidence"`
	CreatedAt       time.Time `json:"created_at"`
}

func (c CredentialFinding) Redacted() CredentialFinding {
	if c.Password != "" {
		c.Password = "********"
	}
	return c
}

type OSINTFinding struct {
	ID         string         `json:"id"`
	SessionID  string         `json:"session_id"`
	Kind       string         `json:"kind"`
	Value      string         `json:"value"`
	Source     string         `json:"source"`
	Confidence float64        `json:"confidence"`
	TargetID   string         `json:"target_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type ADEntity struct {
	ID                string         `json:"id"`
	SessionID         string         `json:"session_id"`
	EntityType        string         `json:"entity_type"`
	Name              string         `json:"name"`
	Domain            string         `json:"domain"`
	SID               string         `json:"sid"`
	DistinguishedName string         `json:"distinguished_name"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

type ADRelationship struct {
	ID           string         `json:"id"`
	SessionID    string         `json:"session_id"`
	FromEntityID string         `json:"from_entity_id"`
	ToEntityID   string         `json:"to_entity_id"`
	Relation     string         `json:"relation"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

type ADArtifact struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	ArtifactType string    `json:"artifact_type"`
	Path         string    `json:"path"`
	Summary      string    `json:"summary"`
	CreatedAt    time.Time `json:"created_at"`
}

type BlockEvent struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	TargetID        string    `json:"target_id,omitempty"`
	ToolID          string    `json:"tool_id"`
	URL             string    `json:"url"`
	StatusCode      int       `json:"status_code"`
	Signal          string    `json:"signal"`
	ResponseSnippet string    `json:"response_snippet"`
	BackoffMS       int       `json:"backoff_ms"`
	CreatedAt       time.Time `json:"created_at"`
}

type PoCStatus string

const (
	PoCStatusPending      PoCStatus = "pending"
	PoCStatusRunning      PoCStatus = "running"
	PoCStatusConfirmed    PoCStatus = "confirmed"
	PoCStatusInconclusive PoCStatus = "inconclusive"
	PoCStatusFailed       PoCStatus = "failed"
)

type PoCResult struct {
	ID               string     `json:"id"`
	SessionID        string     `json:"session_id"`
	FindingID        string     `json:"finding_id"`
	TargetID         string     `json:"target_id,omitempty"`
	PoCType          string     `json:"poc_type"`
	Status           PoCStatus  `json:"status"`
	PayloadID        string     `json:"payload_id,omitempty"`
	RequestRaw       string     `json:"request_raw"`
	ResponseRaw      string     `json:"response_raw"`
	ResponseCode     int        `json:"response_code"`
	ResponseTimeMS   int64      `json:"response_time_ms"`
	Evidence         string     `json:"evidence"`
	CanaryToken      string     `json:"canary_token"`
	CallbackReceived bool       `json:"callback_received"`
	ImpactNarrative  string     `json:"impact_narrative"`
	CreatedAt        time.Time  `json:"created_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

type BurpConfig struct {
	ID                   string    `json:"id"`
	BaseURL              string    `json:"base_url"`
	APIKey               string    `json:"api_key,omitempty"`
	AllowedHosts         []string  `json:"-"`
	CollaboratorProvider string    `json:"collaborator_provider"`
	CollaboratorURL      string    `json:"collaborator_url"`
	InteractshToken      string    `json:"interactsh_token,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func (c BurpConfig) Redacted() BurpConfig {
	if c.APIKey != "" {
		c.APIKey = "********"
	}
	if c.InteractshToken != "" {
		c.InteractshToken = "********"
	}
	return c
}

type BurpCallback struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	FindingID string    `json:"finding_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	SourceIP  string    `json:"source_ip"`
	RawEvent  string    `json:"raw_event"`
	CreatedAt time.Time `json:"created_at"`
}

type BurpImportResult struct {
	TargetsImported   int `json:"targets_imported"`
	FindingsImported  int `json:"findings_imported"`
	EvidenceImported  int `json:"evidence_imported"`
	SkippedOutOfScope int `json:"skipped_out_of_scope,omitempty"`
}

type ProviderStatus struct {
	ID        string         `json:"id"`
	SessionID string         `json:"session_id"`
	Provider  string         `json:"provider"`
	Module    string         `json:"module"`
	Status    string         `json:"status"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type PowerCallback struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	FindingID string    `json:"finding_id,omitempty"`
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	SourceIP  string    `json:"source_ip"`
	RawEvent  string    `json:"raw_event"`
	Received  bool      `json:"received"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
