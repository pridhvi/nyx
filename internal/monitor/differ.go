package monitor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

type Differ struct {
	SessionDir string
}

func (d Differ) DiffSessions(ctx context.Context, baselineSessionID, currentSessionID string, runID string) ([]models.SurfaceChange, error) {
	if strings.TrimSpace(baselineSessionID) == "" {
		return nil, nil
	}
	baseline, err := db.OpenSession(ctx, d.SessionDir, baselineSessionID)
	if err != nil {
		return nil, err
	}
	defer baseline.Close()
	current, err := db.OpenSession(ctx, d.SessionDir, currentSessionID)
	if err != nil {
		return nil, err
	}
	defer current.Close()
	baseTargets, err := baseline.ListTargets(ctx, baselineSessionID)
	if err != nil {
		return nil, err
	}
	currentTargets, err := current.ListTargets(ctx, currentSessionID)
	if err != nil {
		return nil, err
	}
	baseFindings, err := baseline.ListFindings(ctx, baselineSessionID, db.FindingFilter{})
	if err != nil {
		return nil, err
	}
	currentFindings, err := current.ListFindings(ctx, currentSessionID, db.FindingFilter{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var changes []models.SurfaceChange
	changes = append(changes, d.targetChanges(runID, currentSessionID, baseTargets, currentTargets, now)...)
	changes = append(changes, d.technologyChanges(runID, currentSessionID, baseTargets, currentTargets, now)...)
	changes = append(changes, d.findingChanges(runID, currentSessionID, baseFindings, currentFindings, now)...)
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Severity == changes[j].Severity {
			return changes[i].Description < changes[j].Description
		}
		return severityRank(changes[i].Severity) > severityRank(changes[j].Severity)
	})
	return changes, nil
}

func (d Differ) targetChanges(runID, sessionID string, baseline, current []models.Target, at time.Time) []models.SurfaceChange {
	base := mapTargets(baseline)
	next := mapTargets(current)
	var changes []models.SurfaceChange
	for key, target := range next {
		if _, ok := base[key]; !ok {
			changeType := models.SurfaceChangeNewService
			severity := models.SeverityLow
			if !hostSeen(target.Host, baseline) {
				changeType = models.SurfaceChangeNewHost
				severity = models.SeverityMedium
			}
			changes = append(changes, newChange(runID, sessionID, changeType, severity, fmt.Sprintf("New exposed surface %s", targetLabel(target)), "", targetLabel(target), target.ID, "", at))
		}
	}
	for key, target := range base {
		if _, ok := next[key]; !ok {
			changeType := models.SurfaceChangeResolvedService
			if !hostSeen(target.Host, current) {
				changeType = models.SurfaceChangeResolvedHost
			}
			changes = append(changes, newChange(runID, sessionID, changeType, models.SeverityInfo, fmt.Sprintf("Previously observed surface is no longer present: %s", targetLabel(target)), targetLabel(target), "", "", "", at))
		}
	}
	return changes
}

func (d Differ) technologyChanges(runID, sessionID string, baseline, current []models.Target, at time.Time) []models.SurfaceChange {
	base := mapTechnologies(baseline)
	next := mapTechnologies(current)
	var changes []models.SurfaceChange
	for key, tech := range next {
		if previous, ok := base[key]; ok {
			if previous.Version != "" && tech.Version != "" && previous.Version != tech.Version {
				changes = append(changes, newChange(runID, sessionID, models.SurfaceChangeServiceChanged, models.SeverityLow, fmt.Sprintf("Technology version changed: %s", tech.Name), previous.Version, tech.Version, tech.TargetID, "", at))
			}
			continue
		}
		changes = append(changes, newChange(runID, sessionID, models.SurfaceChangeNewTechnology, models.SeverityLow, fmt.Sprintf("New technology detected: %s", tech.Name), "", techLabel(tech), tech.TargetID, "", at))
	}
	return changes
}

func (d Differ) findingChanges(runID, sessionID string, baseline, current []models.Finding, at time.Time) []models.SurfaceChange {
	base := mapFindings(baseline)
	next := mapFindings(current)
	var changes []models.SurfaceChange
	for key, finding := range next {
		if previous, ok := base[key]; ok {
			if previous.Severity != finding.Severity {
				changes = append(changes, newChange(runID, sessionID, models.SurfaceChangeSeverityChanged, finding.Severity, fmt.Sprintf("Finding severity changed: %s", finding.Title), string(previous.Severity), string(finding.Severity), finding.TargetID, finding.ID, at))
			}
			continue
		}
		if _, ok := base[key]; !ok {
			changes = append(changes, newChange(runID, sessionID, models.SurfaceChangeNewFinding, finding.Severity, fmt.Sprintf("New finding: %s", finding.Title), "", findingLabel(finding), finding.TargetID, finding.ID, at))
		}
	}
	for key, finding := range base {
		if _, ok := next[key]; !ok {
			changes = append(changes, newChange(runID, sessionID, models.SurfaceChangeResolvedFinding, models.SeverityInfo, fmt.Sprintf("Finding no longer observed: %s", finding.Title), findingLabel(finding), "", finding.TargetID, finding.ID, at))
		}
	}
	return changes
}

func newChange(runID, sessionID string, changeType models.SurfaceChangeType, severity models.Severity, description, previous, current, targetID, findingID string, at time.Time) models.SurfaceChange {
	return models.SurfaceChange{
		ID:            models.NewID(),
		MonitorRunID:  runID,
		SessionID:     sessionID,
		ChangeType:    changeType,
		Severity:      severity,
		Description:   description,
		PreviousValue: previous,
		CurrentValue:  current,
		TargetID:      targetID,
		FindingID:     findingID,
		CreatedAt:     at,
	}
}

func mapTargets(targets []models.Target) map[string]models.Target {
	out := make(map[string]models.Target, len(targets))
	for _, target := range targets {
		out[targetKey(target)] = target
	}
	return out
}

func targetKey(target models.Target) string {
	host := strings.ToLower(strings.TrimSpace(target.Host))
	if parsed := net.ParseIP(host); parsed != nil {
		host = parsed.String()
	}
	return fmt.Sprintf("%s://%s:%d", strings.ToLower(target.Protocol), host, target.Port)
}

func targetLabel(target models.Target) string {
	return targetKey(target)
}

func hostSeen(host string, targets []models.Target) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, target := range targets {
		if strings.EqualFold(strings.TrimSpace(target.Host), host) {
			return true
		}
	}
	return false
}

func mapTechnologies(targets []models.Target) map[string]models.Technology {
	out := map[string]models.Technology{}
	targetKeys := map[string]string{}
	for _, target := range targets {
		targetKeys[target.ID] = targetKey(target)
		for _, tech := range target.Technologies {
			key := fmt.Sprintf("%s|%s|%s", targetKey(target), strings.ToLower(tech.Category), strings.ToLower(tech.Name))
			out[key] = tech
		}
	}
	_ = targetKeys
	return out
}

func techLabel(tech models.Technology) string {
	if tech.Version == "" {
		return tech.Name
	}
	return tech.Name + " " + tech.Version
}

func mapFindings(findings []models.Finding) map[string]models.Finding {
	out := make(map[string]models.Finding, len(findings))
	for _, finding := range findings {
		out[findingKey(finding)] = finding
	}
	return out
}

func findingKey(finding models.Finding) string {
	normalizedURL := finding.URL
	if parsed, err := url.Parse(finding.URL); err == nil && parsed.Host != "" {
		parsed.Fragment = ""
		normalizedURL = parsed.String()
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(finding.ToolID)),
		strings.ToLower(strings.TrimSpace(string(finding.Type))),
		strings.ToLower(strings.TrimSpace(normalizedURL)),
		strings.ToLower(strings.TrimSpace(finding.Method)),
		strings.ToLower(strings.TrimSpace(finding.Parameter)),
		strings.ToLower(strings.TrimSpace(finding.Title)),
	}
	return strings.Join(parts, "|")
}

func findingLabel(finding models.Finding) string {
	if finding.URL != "" {
		return finding.Title + " @ " + finding.URL
	}
	return finding.Title
}

func severityRank(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	default:
		return 1
	}
}
