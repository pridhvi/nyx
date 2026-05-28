package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type NewSessionInput struct {
	Target         string
	SourcePath     string
	Name           string
	Mode           models.ScanMode
	WorkloadMode   models.WorkloadMode
	OutOfScope     []string
	EnabledPhases  []string
	EnabledTools   []string
	ToolParameters map[string]map[string]any
	RunnerOptions  models.ScanRunnerOptions
	LLMModel       string
	LLMBaseURL     string
}

func NewPendingSourceSession(input NewSessionInput) (models.Session, error) {
	sourcePath := strings.TrimSpace(input.SourcePath)
	if sourcePath == "" {
		return models.Session{}, fmt.Errorf("source path is required")
	}
	mode := input.Mode
	if mode == "" {
		mode = models.ScanModePassive
	}
	switch mode {
	case models.ScanModePassive, models.ScanModeActive, models.ScanModeStealth:
	default:
		return models.Session{}, fmt.Errorf("unsupported scan mode %q", mode)
	}
	name := input.Name
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("Audit %s", sourcePath)
	}
	return models.Session{
		ID:             models.NewID(),
		Name:           name,
		Status:         models.SessionStatusPending,
		Mode:           mode,
		WorkloadMode:   models.WorkloadModeStatic,
		SourcePath:     sourcePath,
		EnabledTools:   input.EnabledTools,
		ToolParameters: input.ToolParameters,
		RunnerOptions:  input.RunnerOptions,
		LLMModel:       input.LLMModel,
		LLMBaseURL:     input.LLMBaseURL,
		CreatedAt:      time.Now().UTC(),
	}, nil
}

func NewPendingSessionWithTargets(input NewSessionInput) (models.Session, []models.Target, error) {
	targetsInput := SplitTargetList(input.Target)
	if len(targetsInput) == 0 {
		return models.Session{}, nil, fmt.Errorf("at least one target is required")
	}
	mode := input.Mode
	if mode == "" {
		mode = models.ScanModeActive
	}
	switch mode {
	case models.ScanModePassive, models.ScanModeActive, models.ScanModeStealth:
	default:
		return models.Session{}, nil, fmt.Errorf("unsupported scan mode %q", mode)
	}
	targetInput := strings.Join(targetsInput, ", ")
	session := models.Session{
		ID:             models.NewID(),
		Name:           input.Name,
		Status:         models.SessionStatusPending,
		Mode:           mode,
		WorkloadMode:   firstWorkloadMode(input.WorkloadMode),
		TargetInput:    targetInput,
		SourcePath:     strings.TrimSpace(input.SourcePath),
		InScope:        targetsInput,
		OutOfScope:     input.OutOfScope,
		EnabledPhases:  input.EnabledPhases,
		EnabledTools:   input.EnabledTools,
		ToolParameters: input.ToolParameters,
		RunnerOptions:  input.RunnerOptions,
		LLMModel:       input.LLMModel,
		LLMBaseURL:     input.LLMBaseURL,
		CreatedAt:      time.Now().UTC(),
	}
	checker, err := NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return models.Session{}, nil, err
	}
	var targets []models.Target
	for _, targetInput := range targetsInput {
		if err := ValidateTargetInput(targetInput); err != nil {
			return models.Session{}, nil, err
		}
		ok, reason := checker.IsInScope(targetInput)
		if !ok {
			return models.Session{}, nil, fmt.Errorf("target %q is out of scope: %s", targetInput, reason)
		}
		targets = append(targets, NewInitialTarget(session.ID, targetInput))
	}
	return session, targets, nil
}

func firstWorkloadMode(mode models.WorkloadMode) models.WorkloadMode {
	switch mode {
	case models.WorkloadModeStatic, models.WorkloadModeCombined:
		return mode
	default:
		return models.WorkloadModeDynamic
	}
}
