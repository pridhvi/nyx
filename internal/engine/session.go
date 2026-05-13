package engine

import (
	"fmt"
	"time"

	"github.com/kanini/nox/internal/models"
)

type NewSessionInput struct {
	Target     string
	Name       string
	Mode       models.ScanMode
	OutOfScope []string
}

func NewPendingSession(input NewSessionInput) (models.Session, models.Target, error) {
	if input.Target == "" {
		return models.Session{}, models.Target{}, fmt.Errorf("target is required")
	}
	mode := input.Mode
	if mode == "" {
		mode = models.ScanModeActive
	}
	switch mode {
	case models.ScanModePassive, models.ScanModeActive, models.ScanModeStealth:
	default:
		return models.Session{}, models.Target{}, fmt.Errorf("unsupported scan mode %q", mode)
	}
	session := models.Session{
		ID:          models.NewID(),
		Name:        input.Name,
		Status:      models.SessionStatusPending,
		Mode:        mode,
		TargetInput: input.Target,
		InScope:     []string{input.Target},
		OutOfScope:  input.OutOfScope,
		CreatedAt:   time.Now().UTC(),
	}
	checker, err := NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return models.Session{}, models.Target{}, err
	}
	ok, reason := checker.IsInScope(input.Target)
	if !ok {
		return models.Session{}, models.Target{}, fmt.Errorf("target is out of scope: %s", reason)
	}
	target := NewInitialTarget(session.ID, input.Target)
	return session, target, nil
}
