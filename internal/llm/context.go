package llm

import (
	"context"

	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

const evidenceLimit = 512

type Store interface {
	GetSession(ctx context.Context) (models.Session, error)
	ListTargets(ctx context.Context, sessionID string) ([]models.Target, error)
	ListFindings(ctx context.Context, sessionID string, filter db.FindingFilter) ([]models.Finding, error)
	ListCVEMatchesBySession(ctx context.Context, sessionID string) ([]models.CVEMatch, error)
	ListAttackVectors(ctx context.Context, sessionID string) ([]models.AttackVector, error)
	Stats(ctx context.Context, sessionID string) (db.SessionStats, error)
	InsertLLMAnalysis(ctx context.Context, analysis models.LLMAnalysis) error
}

type SessionContext struct {
	Session       models.Session        `json:"session"`
	Stats         db.SessionStats       `json:"stats"`
	Targets       []models.Target       `json:"targets"`
	Findings      []models.Finding      `json:"findings"`
	CVEMatches    []models.CVEMatch     `json:"cve_matches"`
	AttackVectors []models.AttackVector `json:"attack_vectors"`
}

func BuildContext(ctx context.Context, store Store, sessionID string) (SessionContext, error) {
	session, err := store.GetSession(ctx)
	if err != nil {
		return SessionContext{}, err
	}
	stats, err := store.Stats(ctx, sessionID)
	if err != nil {
		return SessionContext{}, err
	}
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return SessionContext{}, err
	}
	findings, err := store.ListFindings(ctx, sessionID, db.FindingFilter{})
	if err != nil {
		return SessionContext{}, err
	}
	cves, err := store.ListCVEMatchesBySession(ctx, sessionID)
	if err != nil {
		return SessionContext{}, err
	}
	vectors, err := store.ListAttackVectors(ctx, sessionID)
	if err != nil {
		return SessionContext{}, err
	}
	for i := range findings {
		truncateFindingEvidence(&findings[i])
	}
	return SessionContext{
		Session:       session,
		Stats:         stats,
		Targets:       targets,
		Findings:      findings,
		CVEMatches:    cves,
		AttackVectors: vectors,
	}, nil
}

func truncateFindingEvidence(finding *models.Finding) {
	finding.EvidenceRaw = truncate(finding.EvidenceRaw, evidenceLimit)
	finding.EvidenceNormalized = truncate(finding.EvidenceNormalized, evidenceLimit)
	if finding.HTTPEvidence != nil {
		finding.HTTPEvidence.RequestRaw = truncate(finding.HTTPEvidence.RequestRaw, evidenceLimit)
		finding.HTTPEvidence.ResponseRaw = truncate(finding.HTTPEvidence.ResponseRaw, evidenceLimit)
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}
