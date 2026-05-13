package adapters

import (
	"context"
	"net/http"

	"github.com/kanini/nox/internal/models"
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
	Scope             ScopeValidator
	HTTPClient        HTTPDoer
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
