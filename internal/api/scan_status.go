package api

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/models"
)

type scanStatusResponse struct {
	ID           string               `json:"id"`
	Status       models.SessionStatus `json:"status"`
	TargetCount  int                  `json:"target_count"`
	FindingCount int                  `json:"finding_count"`
	StartedAt    *time.Time           `json:"started_at,omitempty"`
	CompletedAt  *time.Time           `json:"completed_at,omitempty"`
	CurrentPhase string               `json:"current_phase,omitempty"`
	ActiveTools  []string             `json:"active_tools,omitempty"`
	Phases       []phaseProgress      `json:"phases"`
	Tools        []toolProgress       `json:"tools"`
	RecentEvents []engine.ScanEvent   `json:"recent_events,omitempty"`
}

type phaseProgress struct {
	Phase          string     `json:"phase"`
	Status         string     `json:"status"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	ToolCount      int        `json:"tool_count"`
	RunningTools   int        `json:"running_tools"`
	CompletedTools int        `json:"completed_tools"`
	FailedTools    int        `json:"failed_tools"`
	FindingCount   int        `json:"finding_count"`
	DurationMS     int64      `json:"duration_ms,omitempty"`
}

type toolProgress struct {
	ToolID       string     `json:"tool_id"`
	Name         string     `json:"name,omitempty"`
	Phase        string     `json:"phase"`
	Status       string     `json:"status"`
	FindingCount int        `json:"finding_count"`
	DurationMS   int64      `json:"duration_ms,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

func (s *Server) buildScanStatus(ctx context.Context, store *db.Store, session models.Session) (scanStatusResponse, error) {
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		return scanStatusResponse{}, err
	}
	events := s.scanManager.EventHistory(session.ID)
	phases, tools := buildScanProgress(session, runs, events, s.progressToolCatalog())
	currentPhase, activeTools := currentProgress(phases, tools)
	recent := append([]engine.ScanEvent(nil), events...)
	sort.SliceStable(recent, func(i, j int) bool { return recent[i].At.After(recent[j].At) })
	if len(recent) > 20 {
		recent = recent[:20]
	}
	return scanStatusResponse{
		ID:           session.ID,
		Status:       session.Status,
		TargetCount:  session.TargetCount,
		FindingCount: session.FindingCount,
		StartedAt:    session.StartedAt,
		CompletedAt:  session.CompletedAt,
		CurrentPhase: currentPhase,
		ActiveTools:  activeTools,
		Phases:       phases,
		Tools:        tools,
		RecentEvents: recent,
	}, nil
}

type progressToolInfo struct {
	ID    string
	Name  string
	Phase string
}

func (s *Server) progressToolCatalog() map[string]progressToolInfo {
	catalog := map[string]progressToolInfo{}
	for _, adapter := range adapters.All() {
		catalog[adapter.ID()] = progressToolInfo{ID: adapter.ID(), Name: adapter.Name(), Phase: string(adapter.Phase())}
	}
	for _, adapter := range adapters.AllStatic() {
		id := "audit/" + adapter.ID()
		catalog[id] = progressToolInfo{ID: id, Name: adapter.Name(), Phase: "audit"}
	}
	for _, plugin := range s.enabledGlobalPlugins() {
		id := "plugin:" + plugin.ID
		catalog[id] = progressToolInfo{ID: id, Name: plugin.Name, Phase: plugin.Phase}
	}
	return catalog
}

func buildScanProgress(session models.Session, runs []models.ToolRun, events []engine.ScanEvent, catalog map[string]progressToolInfo) ([]phaseProgress, []toolProgress) {
	phaseStates := map[string]*phaseProgress{}
	for _, phase := range scanPhasePlan(session) {
		phaseStates[phase] = &phaseProgress{Phase: phase, Status: "pending"}
	}
	tools := toolProgressFromSession(session, catalog)
	for index := range tools {
		tool := &tools[index]
		phase := ensurePhase(phaseStates, tool.Phase)
		phase.ToolCount++
	}
	for _, run := range runs {
		tool := ensureTool(&tools, run.ToolID, catalog)
		if tool.Phase == "" {
			tool.Phase = "unknown"
		}
		if tool.Name == "" {
			tool.Name = run.ToolID
		}
		started := run.StartedAt
		completed := run.StartedAt.Add(time.Duration(run.DurationMS) * time.Millisecond)
		tool.StartedAt = minTimePtr(tool.StartedAt, started)
		tool.CompletedAt = maxTimePtr(tool.CompletedAt, completed)
		tool.DurationMS += run.DurationMS
		tool.FindingCount += run.FindingCount
		if run.ExitCode == 0 {
			tool.Status = terminalToolStatus(tool.Status, "completed")
		} else {
			tool.Status = "failed"
		}
		phase := ensurePhase(phaseStates, tool.Phase)
		if phase.StartedAt == nil || started.Before(*phase.StartedAt) {
			phase.StartedAt = &started
		}
		if phase.CompletedAt == nil || completed.After(*phase.CompletedAt) {
			phase.CompletedAt = &completed
		}
		phase.FindingCount += run.FindingCount
		phase.DurationMS += run.DurationMS
	}
	for _, event := range events {
		if event.Phase != "" {
			phase := ensurePhase(phaseStates, event.Phase)
			eventAt := event.At
			switch event.Type {
			case engine.ScanEventPhaseStarted:
				phase.StartedAt = minTimePtr(phase.StartedAt, eventAt)
				if phase.Status == "pending" {
					phase.Status = "running"
				}
			case engine.ScanEventPhaseCompleted:
				phase.CompletedAt = maxTimePtr(phase.CompletedAt, eventAt)
				if event.Status == "failed" {
					phase.Status = "failed"
				} else {
					phase.Status = "completed"
				}
				if event.FindingCount > phase.FindingCount {
					phase.FindingCount = event.FindingCount
				}
			}
		}
		if event.ToolID == "" {
			continue
		}
		tool := ensureTool(&tools, event.ToolID, catalog)
		if event.Phase != "" {
			tool.Phase = event.Phase
		}
		if tool.Phase == "" {
			tool.Phase = "unknown"
		}
		if tool.Name == "" {
			tool.Name = event.ToolID
		}
		eventAt := event.At
		switch event.Type {
		case engine.ScanEventToolStarted:
			tool.Status = "running"
			tool.StartedAt = minTimePtr(tool.StartedAt, eventAt)
		case engine.ScanEventToolError:
			tool.Status = "failed"
		case engine.ScanEventToolCompleted:
			if event.Status == "failed" {
				tool.Status = "failed"
			} else if tool.Status != "failed" {
				tool.Status = "completed"
			}
			tool.CompletedAt = maxTimePtr(tool.CompletedAt, eventAt)
			if event.DurationMS > 0 && tool.DurationMS == 0 {
				tool.DurationMS = event.DurationMS
			}
			if event.FindingCount > tool.FindingCount {
				tool.FindingCount = event.FindingCount
			}
		}
		ensurePhase(phaseStates, tool.Phase)
	}
	recountPhaseTools(phaseStates, tools)
	for _, phase := range phaseStates {
		if phase.Status == "pending" {
			if phase.FailedTools > 0 {
				phase.Status = "failed"
			} else if phase.RunningTools > 0 {
				phase.Status = "running"
			} else if phase.ToolCount > 0 && phase.CompletedTools == phase.ToolCount {
				phase.Status = "completed"
			}
		}
	}
	phases := orderedPhaseProgress(phaseStates, scanPhasePlan(session))
	sort.SliceStable(tools, func(i, j int) bool {
		if tools[i].Phase == tools[j].Phase {
			return tools[i].ToolID < tools[j].ToolID
		}
		return phaseOrderIndex(tools[i].Phase, phases) < phaseOrderIndex(tools[j].Phase, phases)
	})
	return phases, tools
}

func scanPhasePlan(session models.Session) []string {
	var phases []string
	add := func(phase string) {
		phase = strings.TrimSpace(phase)
		if phase == "" {
			return
		}
		for _, existing := range phases {
			if existing == phase {
				return
			}
		}
		phases = append(phases, phase)
	}
	switch session.WorkloadMode {
	case models.WorkloadModeStatic:
		if strings.TrimSpace(session.SourcePath) != "" {
			add("source_analysis")
		}
		add("audit")
	case models.WorkloadModeCombined:
		if strings.TrimSpace(session.SourcePath) != "" {
			add("source_analysis")
		}
		add("audit")
		for _, phase := range session.EnabledPhases {
			add(phase)
		}
		if len(session.EnabledPhases) == 0 {
			add("recon")
			add("fingerprint")
			add("enumerate")
			add("vuln_scan")
		}
		add("dynamic")
	default:
		for _, phase := range session.EnabledPhases {
			add(phase)
		}
		if len(session.EnabledPhases) == 0 {
			add("recon")
			add("fingerprint")
			add("enumerate")
			add("vuln_scan")
		}
	}
	add("correlation")
	return phases
}

func toolProgressFromSession(session models.Session, catalog map[string]progressToolInfo) []toolProgress {
	selected := map[string]struct{}{}
	for _, id := range session.EnabledTools {
		id = strings.TrimSpace(id)
		if id != "" {
			selected[id] = struct{}{}
		}
	}
	if len(selected) == 0 {
		for id, info := range catalog {
			if id == "crtsh" || strings.HasPrefix(id, "audit/") || strings.HasPrefix(id, "plugin:") {
				continue
			}
			selected[id] = struct{}{}
			_ = info
		}
	}
	tools := make([]toolProgress, 0, len(selected))
	for id := range selected {
		info := catalog[id]
		phase := info.Phase
		if phase == "" && strings.HasPrefix(id, "audit/") {
			phase = "audit"
		}
		tools = append(tools, toolProgress{ToolID: id, Name: firstNonEmpty(info.Name, id), Phase: phase, Status: "pending"})
	}
	return tools
}

func ensurePhase(phases map[string]*phaseProgress, phase string) *phaseProgress {
	if phase == "" {
		phase = "unknown"
	}
	if phases[phase] == nil {
		phases[phase] = &phaseProgress{Phase: phase, Status: "pending"}
	}
	return phases[phase]
}

func ensureTool(tools *[]toolProgress, toolID string, catalog map[string]progressToolInfo) *toolProgress {
	for index := range *tools {
		if (*tools)[index].ToolID == toolID {
			return &(*tools)[index]
		}
	}
	info := catalog[toolID]
	*tools = append(*tools, toolProgress{ToolID: toolID, Name: firstNonEmpty(info.Name, toolID), Phase: info.Phase, Status: "pending"})
	return &(*tools)[len(*tools)-1]
}

func recountPhaseTools(phases map[string]*phaseProgress, tools []toolProgress) {
	for _, phase := range phases {
		phase.ToolCount = 0
		phase.RunningTools = 0
		phase.CompletedTools = 0
		phase.FailedTools = 0
	}
	for _, tool := range tools {
		phase := ensurePhase(phases, tool.Phase)
		phase.ToolCount++
		switch tool.Status {
		case "running":
			phase.RunningTools++
		case "failed":
			phase.FailedTools++
		case "completed":
			phase.CompletedTools++
		}
	}
}

func orderedPhaseProgress(states map[string]*phaseProgress, preferred []string) []phaseProgress {
	var phases []phaseProgress
	seen := map[string]struct{}{}
	for _, phase := range preferred {
		if state := states[phase]; state != nil {
			phases = append(phases, *state)
			seen[phase] = struct{}{}
		}
	}
	var extras []string
	for phase := range states {
		if _, ok := seen[phase]; !ok {
			extras = append(extras, phase)
		}
	}
	sort.Strings(extras)
	for _, phase := range extras {
		phases = append(phases, *states[phase])
	}
	return phases
}

func currentProgress(phases []phaseProgress, tools []toolProgress) (string, []string) {
	for _, phase := range phases {
		if phase.Status == "running" {
			var active []string
			for _, tool := range tools {
				if tool.Phase == phase.Phase && tool.Status == "running" {
					active = append(active, tool.ToolID)
				}
			}
			sort.Strings(active)
			return phase.Phase, active
		}
	}
	return "", nil
}

func terminalToolStatus(current, next string) string {
	if current == "failed" {
		return current
	}
	return next
}

func minTimePtr(current *time.Time, candidate time.Time) *time.Time {
	if candidate.IsZero() {
		return current
	}
	if current == nil || candidate.Before(*current) {
		copy := candidate
		return &copy
	}
	return current
}

func maxTimePtr(current *time.Time, candidate time.Time) *time.Time {
	if candidate.IsZero() {
		return current
	}
	if current == nil || candidate.After(*current) {
		copy := candidate
		return &copy
	}
	return current
}

func phaseOrderIndex(phase string, phases []phaseProgress) int {
	for index, item := range phases {
		if item.Phase == phase {
			return index
		}
	}
	return len(phases)
}
