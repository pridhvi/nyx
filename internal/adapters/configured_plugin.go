package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

const pluginProtocolVersion = "nyx.plugin.v1"

type ConfiguredPlugin struct {
	record models.PluginRecord
}

func NewConfiguredPlugin(record models.PluginRecord) ConfiguredPlugin {
	return ConfiguredPlugin{record: record}
}

func (p ConfiguredPlugin) ID() string { return "plugin:" + p.record.Name }

func (p ConfiguredPlugin) Name() string { return p.record.Name }

func (p ConfiguredPlugin) Phase() Phase {
	switch Phase(p.record.Phase) {
	case PhaseRecon, PhaseFingerprint, PhaseEnumerate, PhaseVulnScan:
		return Phase(p.record.Phase)
	default:
		return PhaseVulnScan
	}
}

func (p ConfiguredPlugin) DependsOn() []string { return nil }

func (p ConfiguredPlugin) ShouldRun(input AdapterInput) bool {
	return p.record.Enabled && input.Target.Host != ""
}

func (p ConfiguredPlugin) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	args := []string{p.record.Binary}
	started := time.Now().UTC()
	run := models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    p.ID(),
		Args:      args,
		StartedAt: started,
	}
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		run.ExitCode = 1
		run.RawStderr = reason
		run.DurationMS = time.Since(started).Milliseconds()
		now := time.Now().UTC()
		run.NormalizedAt = &now
		return AdapterOutput{ToolRun: run}, nil
	}
	resp, err := RunPlugin(ctx, p.record.Binary, p.record.SHA256, PluginRequest{
		Version:   pluginProtocolVersion,
		SessionID: input.Session.ID,
		Target:    input.Target,
		Config: map[string]string{
			"plugin_name": p.record.Name,
		},
	})
	run.DurationMS = time.Since(started).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	if err != nil {
		run.ExitCode = 1
		run.RawStderr = err.Error()
		return AdapterOutput{ToolRun: run}, nil
	}
	normalized := map[string]any{
		"version":       resp.Version,
		"finding_count": len(resp.Findings),
		"target_count":  len(resp.NewTargets),
		"tech_count":    len(resp.Technologies),
	}
	body, marshalErr := marshalPluginSummary(normalized)
	if marshalErr != nil {
		run.ExitCode = 1
		run.RawStderr = marshalErr.Error()
		return AdapterOutput{ToolRun: run}, nil
	}
	run.RawStdout = body
	run.FindingCount = len(resp.Findings)
	normalizePluginOutput(input, p.ID(), &resp)
	return AdapterOutput{
		Findings:     resp.Findings,
		NewTargets:   resp.NewTargets,
		Technologies: resp.Technologies,
		ToolRun:      run,
	}, nil
}

func normalizePluginOutput(input AdapterInput, toolID string, resp *PluginResponse) {
	for i := range resp.Findings {
		if resp.Findings[i].ID == "" {
			resp.Findings[i].ID = models.NewID()
		}
		if resp.Findings[i].SessionID == "" {
			resp.Findings[i].SessionID = input.Session.ID
		}
		if resp.Findings[i].TargetID == "" {
			resp.Findings[i].TargetID = input.Target.ID
		}
		if resp.Findings[i].ToolID == "" {
			resp.Findings[i].ToolID = toolID
		}
		if resp.Findings[i].CreatedAt.IsZero() {
			resp.Findings[i].CreatedAt = time.Now().UTC()
		}
	}
	for i := range resp.NewTargets {
		if resp.NewTargets[i].ID == "" {
			resp.NewTargets[i].ID = models.NewID()
		}
		if resp.NewTargets[i].SessionID == "" {
			resp.NewTargets[i].SessionID = input.Session.ID
		}
		if resp.NewTargets[i].CreatedAt.IsZero() {
			resp.NewTargets[i].CreatedAt = time.Now().UTC()
		}
	}
	for i := range resp.Technologies {
		if resp.Technologies[i].ID == "" {
			resp.Technologies[i].ID = models.NewID()
		}
		if resp.Technologies[i].TargetID == "" {
			resp.Technologies[i].TargetID = input.Target.ID
		}
		if resp.Technologies[i].SourceTool == "" {
			resp.Technologies[i].SourceTool = toolID
		}
	}
}

func marshalPluginSummary(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal plugin summary: %w", err)
	}
	return string(body), nil
}
