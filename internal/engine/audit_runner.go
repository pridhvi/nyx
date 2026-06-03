package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/source"
	"github.com/pridhvi/nyx/internal/suppress"
)

type AuditOptions struct {
	Tools           []string
	DiffPaths       []string
	NoLLM           bool
	Offline         bool
	KeepSessionOpen bool
	LLMConfig       llmintel.Config
}

type AuditRunner struct {
	store    *db.Store
	adapters []adapters.StaticAdapter
	onEvent  ScanEventHandler
	options  AuditOptions
}

func NewAuditRunner(store *db.Store, options AuditOptions) *AuditRunner {
	return &AuditRunner{store: store, adapters: adapters.AllStatic(), options: options}
}

func (r *AuditRunner) OnEvent(handler ScanEventHandler) {
	r.onEvent = handler
}

func (r *AuditRunner) Run(ctx context.Context, session models.Session, repoPath string) error {
	started := time.Now().UTC()
	if err := r.store.UpdateSessionStatus(ctx, session.ID, models.SessionStatusRunning, &started, nil); err != nil {
		return err
	}
	existingSource, _ := r.store.ListSourceFindings(ctx, session.ID, db.SourceFindingFilter{})
	analysis := source.AnalysisResult{Language: "unknown", Framework: "unknown", Findings: existingSource}
	if len(existingSource) == 0 {
		r.emit(ScanEvent{Type: ScanEventPhaseStarted, SessionID: session.ID, Phase: "source_analysis", Message: "Source analysis started", At: time.Now().UTC()})
		var err error
		analysis, err = source.Analyse(repoPath, session.ID)
		if err != nil {
			slog.Warn("source analysis skipped", "repo", repoPath, "error", err)
		}
		for _, finding := range analysis.Findings {
			if err := r.store.InsertSourceFinding(ctx, finding); err != nil {
				return err
			}
		}
		r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "source_analysis", Message: "Source analysis completed", FindingCount: len(analysis.Findings), At: time.Now().UTC()})
	}

	rules, err := suppress.Parse(repoPath)
	if err != nil {
		return err
	}
	staticAdapters, err := r.selectedAdapters(analysis.Language)
	if err != nil {
		return err
	}
	r.emit(ScanEvent{Type: ScanEventPhaseStarted, SessionID: session.ID, Phase: "audit", Message: "Static audit started", At: time.Now().UTC()})
	var mu sync.Mutex
	var dbMu sync.Mutex
	var allFindings []models.Finding
	var auditErr error
	var wg sync.WaitGroup
	for _, adapter := range staticAdapters {
		adapter := adapter
		if !adapter.Available() {
			if r.explicitlySelected(adapter.ID()) {
				return fmt.Errorf("required audit tool %s is not available", adapter.ID())
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			output, err := adapter.Run(ctx, adapters.StaticAdapterInput{
				SessionID:        session.ID,
				RepoPath:         repoPath,
				Language:         analysis.Language,
				Framework:        analysis.Framework,
				DiffPaths:        r.options.DiffPaths,
				SuppressionRules: rules,
				Offline:          r.options.Offline,
			})
			if err != nil {
				slog.Warn("audit adapter failed", "tool", adapter.ID(), "error", err)
			}
			run := output.ToolRun
			run.ToolID = auditToolID(adapter.ID())
			stdoutPath, stderrPath := r.writeRunLogs(session.ID, run.ID, run.RawStdout, run.RawStderr)
			run.StdoutPath = stdoutPath
			run.StderrPath = stderrPath
			dbMu.Lock()
			if insertErr := r.store.InsertToolRun(context.WithoutCancel(ctx), run); insertErr != nil {
				dbMu.Unlock()
				mu.Lock()
				auditErr = insertErr
				mu.Unlock()
				return
			}
			dbMu.Unlock()
			filtered := filterAuditFindingsByDiff(applySuppression(output.Findings, rules), r.options.DiffPaths)
			if r.options.NoLLM || !r.options.LLMConfig.Configured() {
				for i := range filtered {
					if filtered[i].Status == "" || filtered[i].Status == models.FindingStatusOpen {
						filtered[i].Status = models.FindingStatusConfirmed
					}
				}
			}
			for _, finding := range filtered {
				if finding.ToolID == adapter.ID() || !strings.HasPrefix(finding.ToolID, "audit/") {
					finding.ToolID = auditToolID(adapter.ID())
				}
				if finding.CreatedAt.IsZero() {
					finding.CreatedAt = time.Now().UTC()
				}
				dbMu.Lock()
				if insertErr := r.store.InsertFinding(context.WithoutCancel(ctx), finding); insertErr != nil {
					dbMu.Unlock()
					mu.Lock()
					auditErr = insertErr
					mu.Unlock()
					return
				}
				dbMu.Unlock()
				mu.Lock()
				allFindings = append(allFindings, finding)
				mu.Unlock()
			}
			for _, cve := range output.CVEs {
				cve.SessionID = session.ID
				if cve.ID == "" {
					cve.ID = models.NewID()
				}
				dbMu.Lock()
				if insertErr := r.store.InsertCVEMatch(context.WithoutCancel(ctx), cve); insertErr != nil {
					dbMu.Unlock()
					mu.Lock()
					auditErr = insertErr
					mu.Unlock()
					return
				}
				dbMu.Unlock()
			}
			r.emit(ScanEvent{Type: ScanEventToolCompleted, SessionID: session.ID, ToolID: run.ToolID, Phase: "audit", Status: "completed", FindingCount: len(filtered), DurationMS: run.DurationMS, At: time.Now().UTC()})
		}()
	}
	wg.Wait()
	if auditErr != nil {
		return auditErr
	}
	if !r.options.NoLLM && r.options.LLMConfig.Configured() && len(allFindings) > 0 {
		_ = llmintel.NewAuditAnalyst(r.store, nil, r.options.LLMConfig).ReviewFindings(ctx, session.ID, allFindings, repoPath)
	}
	if err := ctx.Err(); err != nil {
		auditErr = err
	}
	if err := r.store.UpdateSessionCounts(context.WithoutCancel(ctx), session.ID); err != nil {
		return err
	}
	completed := time.Now().UTC()
	if !r.options.KeepSessionOpen {
		status := models.SessionStatusCompleted
		if auditErr != nil {
			status = models.SessionStatusFailed
			if errors.Is(auditErr, context.Canceled) {
				status = models.SessionStatusCancelled
			}
		}
		if err := r.store.UpdateSessionStatus(context.WithoutCancel(ctx), session.ID, status, nil, &completed); err != nil {
			return err
		}
	}
	r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "audit", Message: "Static audit completed", FindingCount: len(allFindings), At: completed})
	return auditErr
}

func (r *AuditRunner) selectedAdapters(language string) ([]adapters.StaticAdapter, error) {
	selected := map[string]bool{}
	for _, tool := range r.options.Tools {
		tool = strings.TrimPrefix(strings.TrimSpace(tool), "audit/")
		if tool != "" {
			selected[tool] = true
		}
	}
	var out []adapters.StaticAdapter
	for _, adapter := range r.adapters {
		if len(selected) > 0 && !selected[adapter.ID()] {
			continue
		}
		if !staticAdapterApplies(adapter, language) {
			continue
		}
		out = append(out, adapter)
	}
	for tool := range selected {
		found := false
		for _, adapter := range out {
			if adapter.ID() == tool {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown or inapplicable audit tool %s", tool)
		}
	}
	return out, nil
}

func staticAdapterApplies(adapter adapters.StaticAdapter, language string) bool {
	for _, supported := range adapter.Languages() {
		if supported == "any" || supported == language {
			return true
		}
	}
	return false
}

func (r *AuditRunner) explicitlySelected(id string) bool {
	for _, tool := range r.options.Tools {
		if strings.TrimPrefix(strings.TrimSpace(tool), "audit/") == id {
			return true
		}
	}
	return false
}

func applySuppression(findings []models.Finding, rules []suppress.Rule) []models.Finding {
	for i := range findings {
		ruleID := ""
		if len(findings[i].Tags) > 0 {
			ruleID = findings[i].Tags[len(findings[i].Tags)-1]
		}
		if suppress.Matches(rules, strings.TrimPrefix(findings[i].ToolID, "audit/"), ruleID, filePathFromURL(findings[i].URL)) {
			findings[i].Status = "suppressed"
		}
	}
	return findings
}

func filterAuditFindingsByDiff(findings []models.Finding, diffPaths []string) []models.Finding {
	if len(diffPaths) == 0 {
		return findings
	}
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		path := filePathFromURL(finding.URL)
		for _, diffPath := range diffPaths {
			diffPath = filepath.ToSlash(strings.TrimSpace(diffPath))
			if diffPath == "" {
				continue
			}
			if filepath.ToSlash(path) == diffPath || strings.HasSuffix(filepath.ToSlash(path), diffPath) {
				out = append(out, finding)
				break
			}
		}
	}
	return out
}

func (r *AuditRunner) writeRunLogs(sessionID, runID, stdout, stderr string) (string, string) {
	if r.store == nil || runID == "" {
		return "", ""
	}
	dir := filepath.Join(filepath.Dir(r.store.Path()), "runs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		slog.Error("create audit log directory", "session_id", sessionID, "run_id", runID, "error", err)
		return "", ""
	}
	stdoutPath := filepath.Join(dir, runID+".stdout.log")
	stderrPath := filepath.Join(dir, runID+".stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o600); err != nil {
		stdoutPath = ""
	}
	if err := os.WriteFile(stderrPath, []byte(stderr), 0o600); err != nil {
		stderrPath = ""
	}
	return stdoutPath, stderrPath
}

func (r *AuditRunner) emit(event ScanEvent) {
	if r.onEvent != nil {
		r.onEvent(event)
	}
}

func auditToolID(id string) string {
	if strings.HasPrefix(id, "audit/") {
		return id
	}
	return "audit/" + id
}

func filePathFromURL(value string) string {
	value = strings.TrimPrefix(value, "file://")
	if idx := strings.Index(value, "#"); idx >= 0 {
		value = value[:idx]
	}
	return value
}
