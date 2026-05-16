package adapters

import (
	"context"
	"net/http"

	"github.com/pridhvi/nox/internal/models"
)

type Phase string

const (
	PhaseRecon       Phase = "recon"
	PhaseFingerprint Phase = "fingerprint"
	PhaseEnumerate   Phase = "enumerate"
	PhaseVulnScan    Phase = "vuln_scan"
)

type AdapterInput struct {
	SessionID         string
	Target            models.Target
	Session           models.Session
	PriorFindings     []models.Finding
	PriorTechnologies []models.Technology
	SourceFindings    []models.SourceFinding
	ToolParameters    map[string]any
	Scope             ScopeValidator
	HTTPClient        HTTPDoer
}

type StaticAdapterInput struct {
	SessionID        string
	RepoPath         string
	Language         string
	Framework        string
	DiffPaths        []string
	SuppressionRules []SuppressionRule
	Offline          bool
}

type StaticAdapterOutput struct {
	Findings []models.Finding
	CVEs     []models.CVEMatch
	ToolRun  models.ToolRun
}

type SuppressionRule struct {
	ToolID   string
	RuleID   string
	PathGlob string
}

type StaticAdapter interface {
	ID() string
	Name() string
	Languages() []string
	Available() bool
	Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error)
}

type AdapterOutput struct {
	Findings     []models.Finding
	NewTargets   []models.Target
	Technologies []models.Technology
	ToolRun      models.ToolRun
}

type Adapter interface {
	ID() string
	Name() string
	Phase() Phase
	DependsOn() []string
	ShouldRun(input AdapterInput) bool
	Run(ctx context.Context, input AdapterInput) (AdapterOutput, error)
}

type ScopeValidator interface {
	IsInScope(raw string) (bool, string)
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
