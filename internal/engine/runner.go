package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	cveintel "github.com/pridhvi/nyx/internal/cve"
	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/source"
	"github.com/pridhvi/nyx/internal/vectors"
)

type Runner struct {
	store      *db.Store
	adapters   []adapters.Adapter
	httpClient adapters.HTTPDoer
	onEvent    ScanEventHandler
	options    RunnerOptions
	pause      pauseController
}

type RunnerOptions struct {
	GlobalConcurrency  int
	PerToolConcurrency int
	ToolDelay          time.Duration
	ToolTimeout        time.Duration
	Lean               bool
	LLMAllowedHosts    []string
}

func NewRunner(store *db.Store) *Runner {
	runner := &Runner{
		store:      store,
		adapters:   DefaultSafeAdapters(),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		options:    defaultRunnerOptions(),
	}
	runner.loadConfiguredPlugins(context.Background())
	return runner
}

func DefaultSafeAdapters() []adapters.Adapter {
	return []adapters.Adapter{
		adapters.NewHTTPProbe(),
		adapters.NewSecurityHeaders(),
		adapters.NewWhatWeb(),
		adapters.NewNucleiTech(),
		adapters.NewTestSSL(),
		adapters.NewGraphQLIntrospection(),
		adapters.NewOpenAPIDiscovery(),
		adapters.NewWPScan(),
		adapters.NewDroopescan(),
		adapters.NewArjun(),
		adapters.NewLinkFinder(),
		adapters.NewGitleaks(),
		adapters.NewJavaScriptSecretScan(),
		adapters.NewCORSCheck(),
		adapters.NewCloudBucketCheck(),
		adapters.NewSubfinder(),
		adapters.NewDNSX(),
		adapters.NewNaabu(),
		adapters.NewHTTPX(),
		adapters.NewWhois(),
		adapters.NewWaybackURLs(),
		adapters.NewCrtSH(),
		adapters.NewNmap(),
		adapters.NewFFUF(),
		adapters.NewBruteForceCheck(),
		adapters.NewReflectedXSSCheck(),
		adapters.NewDOMXSSCheck(),
		adapters.NewStoredXSSCheck(),
		adapters.NewOpenRedirectCheck(),
		adapters.NewSQLICheck(),
		adapters.NewFileInclusionCheck(),
		adapters.NewCommandInjectionCheck(),
		adapters.NewUploadCheck(),
		adapters.NewIDORCheck(),
		adapters.NewWorkflowAssistCheck(),
		adapters.NewObservabilityAssistCheck(),
		adapters.NewDeserializationAssistCheck(),
		adapters.NewCSPReviewCheck(),
		adapters.NewCSRFCheck(),
		adapters.NewWeakSessionIDCheck(),
		adapters.NewSSTICheck(),
		adapters.NewXXEFuzz(),
		adapters.NewNucleiVuln(),
		adapters.NewSSRFMap(),
		adapters.NewJWTTool(),
		adapters.NewOAuthCheck(),
		adapters.NewNikto(),
		adapters.NewSQLMap(),
		adapters.NewDalfox(),
	}
}

func NewRunnerWithHTTPClient(store *db.Store, client adapters.HTTPDoer) *Runner {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	runner := &Runner{store: store, adapters: DefaultSafeAdapters(), httpClient: client, options: defaultRunnerOptions()}
	runner.loadConfiguredPlugins(context.Background())
	return runner
}

func NewRunnerWithAdapters(store *db.Store, scanAdapters []adapters.Adapter, client adapters.HTTPDoer) *Runner {
	return &Runner{store: store, adapters: scanAdapters, httpClient: client, options: defaultRunnerOptions()}
}

func NewRunnerWithOptions(store *db.Store, scanAdapters []adapters.Adapter, client adapters.HTTPDoer, options RunnerOptions) *Runner {
	runner := &Runner{store: store, adapters: scanAdapters, httpClient: client, options: normalizeRunnerOptions(options)}
	runner.loadConfiguredPlugins(context.Background())
	return runner
}

func defaultRunnerOptions() RunnerOptions {
	return RunnerOptions{GlobalConcurrency: 4, PerToolConcurrency: 1}
}

func normalizeRunnerOptions(options RunnerOptions) RunnerOptions {
	if options.GlobalConcurrency <= 0 {
		options.GlobalConcurrency = 4
	}
	if options.PerToolConcurrency <= 0 {
		options.PerToolConcurrency = 1
	}
	return options
}

func (r *Runner) OnEvent(handler ScanEventHandler) {
	r.onEvent = handler
}

func (r *Runner) AddAdapters(scanAdapters ...adapters.Adapter) {
	r.adapters = append(r.adapters, scanAdapters...)
}

func (r *Runner) SetPauseController(controller pauseController) {
	r.pause = controller
}

type pauseController interface {
	WaitIfPaused(context.Context) error
}

type authRefreshState struct {
	enabled           bool
	target            models.Target
	scope             *ScopeChecker
	hasValidation     bool
	validateEachPhase bool
	interval          time.Duration
	lastCheck         time.Time
	lastResolve       time.Time
}

func newAuthRefreshState(session models.Session, target models.Target, scope *ScopeChecker) authRefreshState {
	return authRefreshState{
		enabled:           true,
		target:            target,
		scope:             scope,
		hasValidation:     adapters.AuthValidationConfigured(session),
		validateEachPhase: adapters.AuthValidateEachPhase(session),
		interval:          adapters.AuthRefreshInterval(session),
	}
}

func (s *authRefreshState) markResolved(at time.Time) {
	s.lastResolve = at
	if s.hasValidation {
		s.lastCheck = at
	}
}

func (s authRefreshState) shouldValidate(now time.Time) bool {
	if !s.enabled || !s.hasValidation {
		return false
	}
	if s.validateEachPhase {
		return true
	}
	return s.interval > 0 && (s.lastCheck.IsZero() || now.Sub(s.lastCheck) >= s.interval)
}

func (s authRefreshState) shouldRefreshWithoutValidation(now time.Time) bool {
	if !s.enabled || s.hasValidation {
		return false
	}
	if s.validateEachPhase {
		return true
	}
	return s.interval > 0 && (s.lastResolve.IsZero() || now.Sub(s.lastResolve) >= s.interval)
}

func (r *Runner) loadConfiguredPlugins(ctx context.Context) {
	if r.store == nil {
		return
	}
	plugins, err := r.store.ListPlugins(ctx)
	if err != nil {
		return
	}
	for _, plugin := range plugins {
		if !plugin.Enabled {
			continue
		}
		r.adapters = append(r.adapters, adapters.NewConfiguredPlugin(plugin))
	}
}

func (r *Runner) Run(ctx context.Context, session models.Session) error {
	started := time.Now().UTC()
	if err := r.store.UpdateSessionStatus(ctx, session.ID, models.SessionStatusRunning, &started, nil); err != nil {
		return err
	}
	r.emit(ScanEvent{
		Type:      ScanEventRunning,
		SessionID: session.ID,
		Status:    string(models.SessionStatusRunning),
		Message:   "Scan running",
		At:        started,
	})
	targets, err := r.store.ListTargets(ctx, session.ID)
	if err != nil {
		return err
	}
	scope, err := NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return err
	}
	authState := authRefreshState{}
	if len(targets) == 1 && adapters.HasAuthProfile(session) {
		authState = newAuthRefreshState(session, targets[0], scope)
		r.emit(ScanEvent{Type: ScanEventPhaseStarted, SessionID: session.ID, Phase: "auth", Message: "Auth profile resolution started", At: time.Now().UTC()})
		result, err := adapters.ResolveSessionAuth(ctx, session, targets[0], scope)
		if err != nil {
			slog.Warn("auth profile skipped", "session_id", session.ID, "error", err)
			r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "auth", Status: "skipped", Message: err.Error(), At: time.Now().UTC()})
		} else if result.Applied {
			session = result.Session
			authState.markResolved(time.Now().UTC())
			r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "auth", Status: "completed", Message: result.Message, At: time.Now().UTC()})
		}
	} else if len(targets) > 1 && adapters.HasAuthProfile(session) {
		slog.Warn("auth profile skipped for multi-target scan", "session_id", session.ID, "target_count", len(targets))
		r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "skipped", Message: "Auth profile skipped for multi-target scan", At: time.Now().UTC()})
	}
	sourceFindings, err := r.loadSourceFindings(ctx, session)
	if err != nil {
		return err
	}
	scanAdapters, err := selectedAdapters(r.adapters, session.EnabledTools, session.EnabledPhases)
	if err != nil {
		return err
	}
	levels, err := adapterLevels(scanAdapters)
	if err != nil {
		return err
	}
	var scanErr error
	cancelled := false
	var priorFindings []models.Finding
	var priorTechnologies []models.Technology
	for _, target := range targets {
		priorTechnologies = append(priorTechnologies, target.Technologies...)
	}
	globalSem := make(chan struct{}, normalizeRunnerOptions(r.options).GlobalConcurrency)
	toolSems := map[string]chan struct{}{}
	for _, adapter := range scanAdapters {
		if toolSems[adapter.ID()] == nil {
			toolSems[adapter.ID()] = make(chan struct{}, normalizeRunnerOptions(r.options).PerToolConcurrency)
		}
	}
	for phaseIndex, level := range levels {
		if err := ctx.Err(); err != nil {
			cancelled = true
			scanErr = err
			break
		}
		phaseName := phaseName(level)
		if authState.enabled {
			refreshed, updatedSession, authErr := r.refreshAuthIfNeeded(ctx, session, &authState, phaseName)
			session = updatedSession
			if authErr != nil {
				slog.Warn("auth profile refresh failed", "session_id", session.ID, "phase", phaseName, "error", authErr)
			}
			if refreshed {
				r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "refreshed", Message: "Auth profile refreshed before phase " + phaseName, At: time.Now().UTC()})
			}
		}
		r.emit(ScanEvent{
			Type:      ScanEventPhaseStarted,
			SessionID: session.ID,
			Phase:     phaseName,
			Message:   fmt.Sprintf("Phase %s started", phaseName),
			At:        time.Now().UTC(),
		})
		results := r.runLevel(ctx, session, level, targets, scope, priorFindings, priorTechnologies, sourceFindings, globalSem, toolSems)
		for _, result := range results {
			if result.ctxErr != nil {
				cancelled = true
				scanErr = result.ctxErr
			}
			persistCtx := ctx
			if ctx.Err() != nil {
				persistCtx = context.WithoutCancel(ctx)
			}
			if persistErr := r.persist(persistCtx, session.ID, result.output); persistErr != nil {
				scanErr = persistErr
			}
			targets = mergeTargets(targets, result.output.NewTargets)
			priorFindings = append(priorFindings, result.output.Findings...)
			priorTechnologies = append(priorTechnologies, result.output.Technologies...)
		}
		r.emit(ScanEvent{
			Type:         ScanEventPhaseCompleted,
			SessionID:    session.ID,
			Phase:        phaseName,
			Status:       "completed",
			Message:      fmt.Sprintf("Phase %s completed", phaseName),
			FindingCount: len(priorFindings),
			At:           time.Now().UTC(),
		})
		if cancelled || (scanErr != nil && ctx.Err() != nil) {
			break
		}
		if phaseIndex == len(levels)-1 {
			break
		}
	}
	finalCtx := context.WithoutCancel(ctx)
	if !cancelled {
		r.emit(ScanEvent{Type: ScanEventPhaseStarted, SessionID: session.ID, Phase: "correlation", Message: "Correlation started", At: time.Now().UTC()})
		if cveErr := r.runCVECorrelation(finalCtx, session); cveErr != nil {
			scanErr = cveErr
		}
		if vectorErr := r.runAttackVectorEngine(finalCtx, session); vectorErr != nil {
			scanErr = vectorErr
		}
		if llmErr := r.runLLMAnalysis(finalCtx, session); llmErr != nil {
			scanErr = llmErr
		}
		r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "correlation", Message: "Correlation completed", At: time.Now().UTC()})
	}
	if err := r.store.UpdateSessionCounts(finalCtx, session.ID); err != nil {
		return err
	}
	completed := time.Now().UTC()
	status := models.SessionStatusCompleted
	if cancelled {
		status = models.SessionStatusCancelled
	} else if scanErr != nil {
		status = models.SessionStatusFailed
	}
	if err := r.store.UpdateSessionStatus(finalCtx, session.ID, status, nil, &completed); err != nil {
		return err
	}
	eventType := ScanEventCompleted
	message := "Scan completed"
	if cancelled {
		eventType = ScanEventCancelled
		message = "Scan cancelled"
	} else if scanErr != nil {
		eventType = ScanEventFailed
		message = scanErr.Error()
	}
	r.emit(ScanEvent{
		Type:      eventType,
		SessionID: session.ID,
		Status:    string(status),
		Message:   message,
		At:        completed,
	})
	return scanErr
}

func (r *Runner) refreshAuthIfNeeded(ctx context.Context, session models.Session, state *authRefreshState, phase string) (bool, models.Session, error) {
	now := time.Now().UTC()
	if state == nil || !state.enabled {
		return false, session, nil
	}
	needsRefresh := state.shouldRefreshWithoutValidation(now)
	if state.shouldValidate(now) {
		if err := adapters.ValidateSessionAuth(ctx, session, state.target, state.scope); err != nil {
			state.lastCheck = now
			r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "invalid", Message: "Auth validation failed before phase " + phase + ": " + err.Error(), At: now})
			needsRefresh = true
		} else {
			state.lastCheck = now
			r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "valid", Message: "Auth validation succeeded before phase " + phase, At: now})
		}
	}
	if !needsRefresh {
		return false, session, nil
	}
	r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "refreshing", Message: "Auth profile refresh started before phase " + phase, At: time.Now().UTC()})
	result, err := adapters.ResolveSessionAuth(ctx, session, state.target, state.scope)
	if err != nil {
		r.emit(ScanEvent{Type: ScanEventAuthStatus, SessionID: session.ID, Phase: "auth", Status: "failed", Message: "Auth profile refresh failed before phase " + phase + ": " + err.Error(), At: time.Now().UTC()})
		return false, session, err
	}
	if !result.Applied {
		return false, session, nil
	}
	state.markResolved(time.Now().UTC())
	return true, result.Session, nil
}

func (r *Runner) runLLMAnalysis(ctx context.Context, session models.Session) error {
	config := llmintel.ConfigFromSession(session)
	if len(r.options.LLMAllowedHosts) > 0 {
		config.AllowedHosts = r.options.LLMAllowedHosts
	}
	if !config.Configured() {
		return nil
	}
	analyst := llmintel.NewAnalyst(r.store, nil, config)
	_, err := analyst.AnalyzeSession(ctx, session.ID, "Review the completed scan. Summarize the highest-confidence risks, relevant CVEs, deterministic attack vectors, and safe follow-up checks.")
	if err != nil {
		return nil
	}
	return nil
}

func (r *Runner) runAttackVectorEngine(ctx context.Context, session models.Session) error {
	findings, err := r.store.ListFindings(ctx, session.ID, db.FindingFilter{})
	if err != nil {
		return err
	}
	cves, err := r.store.ListCVEMatchesBySession(ctx, session.ID)
	if err != nil {
		return err
	}
	sourceFindings, err := r.store.ListSourceFindings(ctx, session.ID, db.SourceFindingFilter{})
	if err != nil {
		return err
	}
	existing, err := r.store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, vector := range existing {
		seen[attackVectorKey(vector)] = true
	}
	generated := vectors.NewEngine().Generate(session.ID, findings, cves)
	graph := vectors.BuildAttackGraph(session.ID, findings, sourceFindings)
	if err := r.store.DeleteAttackGraphEdges(ctx, session.ID); err != nil {
		return err
	}
	for _, edge := range graph.Edges {
		if strings.HasPrefix(edge.FromID, "source:") && edge.Relation == models.RelationConfirms {
			_ = r.store.MarkSourceFindingConfirmed(ctx, strings.TrimPrefix(edge.FromID, "source:"))
		}
		if err := r.store.InsertAttackGraphEdge(ctx, edge); err != nil {
			return err
		}
	}
	generated = append(generated, vectors.VectorsFromGraph(session.ID, graph)...)
	for _, vector := range generated {
		if seen[attackVectorKey(vector)] {
			continue
		}
		if err := r.store.InsertAttackVector(ctx, vector); err != nil {
			return err
		}
		seen[attackVectorKey(vector)] = true
	}
	return nil
}

func attackVectorKey(vector models.AttackVector) string {
	prereqs := append([]string(nil), vector.PrereqFindingIDs...)
	sort.Strings(prereqs)
	return vector.Title + ":" + strings.Join(prereqs, ",")
}

func (r *Runner) runCVECorrelation(ctx context.Context, session models.Session) error {
	targets, err := r.store.ListTargets(ctx, session.ID)
	if err != nil {
		return err
	}
	findings, err := r.store.ListFindings(ctx, session.ID, db.FindingFilter{})
	if err != nil {
		return err
	}
	result, err := cveintel.NewDefaultCorrelator().Correlate(ctx, session, targets, findings)
	if err != nil {
		return err
	}
	for _, match := range result.Matches {
		if exists, err := r.cveMatchExists(ctx, match); err != nil {
			return err
		} else if exists {
			continue
		}
		if err := r.store.InsertCVEMatch(ctx, match); err != nil {
			return err
		}
	}
	for _, vector := range result.Vectors {
		if err := r.store.InsertAttackVector(ctx, vector); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) cveMatchExists(ctx context.Context, match models.CVEMatch) (bool, error) {
	var matches []models.CVEMatch
	var err error
	if match.TechnologyID != "" {
		matches, err = r.store.ListCVEMatchesByTechnology(ctx, match.TechnologyID)
	} else if match.FindingID != "" {
		matches, err = r.store.ListCVEMatchesByFinding(ctx, match.FindingID)
	}
	if err != nil {
		return false, err
	}
	for _, existing := range matches {
		if existing.CVEID == match.CVEID {
			return true, nil
		}
	}
	return false, nil
}

func (r *Runner) persist(ctx context.Context, sessionID string, output adapters.AdapterOutput) error {
	for _, target := range output.NewTargets {
		if err := r.store.UpdateTarget(ctx, target); err != nil {
			return err
		}
	}
	for _, technology := range output.Technologies {
		if err := r.store.InsertTechnology(ctx, technology); err != nil {
			return err
		}
	}
	for _, finding := range output.Findings {
		if err := r.store.InsertFinding(ctx, finding); err != nil {
			return err
		}
		r.emit(ScanEvent{
			Type:         ScanEventFindingFound,
			SessionID:    finding.SessionID,
			TargetID:     finding.TargetID,
			ToolID:       finding.ToolID,
			FindingID:    finding.ID,
			FindingTitle: finding.Title,
			Severity:     string(finding.Severity),
			Message:      finding.Title,
			At:           finding.CreatedAt,
		})
	}
	if output.ToolRun.ID != "" {
		run := output.ToolRun
		stdoutPath, stderrPath := r.writeRunLogs(sessionID, run.ID, run.RawStdout, run.RawStderr)
		run.StdoutPath = stdoutPath
		run.StderrPath = stderrPath
		if r.options.Lean {
			removeRunLog(stdoutPath)
			removeRunLog(stderrPath)
			run.StdoutPath = ""
			run.StderrPath = ""
		}
		if err := r.store.InsertToolRun(ctx, run); err != nil {
			return err
		}
	}
	return r.store.UpdateSessionCounts(ctx, sessionID)
}

func (r *Runner) writeRunLogs(sessionID, runID, stdout, stderr string) (string, string) {
	if r.store == nil || runID == "" {
		return "", ""
	}
	dir := filepath.Join(filepath.Dir(r.store.Path()), "runs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		slog.Error("create tool run log directory", "session_id", sessionID, "run_id", runID, "error", err)
		return "", ""
	}
	stdoutPath := filepath.Join(dir, runID+".stdout.log")
	stderrPath := filepath.Join(dir, runID+".stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o600); err != nil {
		slog.Error("write tool stdout log", "session_id", sessionID, "run_id", runID, "error", err)
		stdoutPath = ""
	}
	if err := os.WriteFile(stderrPath, []byte(stderr), 0o600); err != nil {
		slog.Error("write tool stderr log", "session_id", sessionID, "run_id", runID, "error", err)
		stderrPath = ""
	}
	return stdoutPath, stderrPath
}

func removeRunLog(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

type adapterRunResult struct {
	output adapters.AdapterOutput
	ctxErr error
}

func (r *Runner) loadSourceFindings(ctx context.Context, session models.Session) ([]models.SourceFinding, error) {
	if strings.TrimSpace(session.SourcePath) != "" {
		r.emit(ScanEvent{Type: ScanEventPhaseStarted, SessionID: session.ID, Phase: "source_analysis", Message: "Source analysis started", At: time.Now().UTC()})
		result, err := source.Analyse(session.SourcePath, session.ID)
		if err != nil {
			slog.Warn("source analysis skipped", "session_id", session.ID, "error", err)
		}
		for _, finding := range result.Findings {
			if err := r.store.InsertSourceFinding(ctx, finding); err != nil {
				return nil, err
			}
		}
		r.emit(ScanEvent{Type: ScanEventPhaseCompleted, SessionID: session.ID, Phase: "source_analysis", Message: "Source analysis completed", FindingCount: len(result.Findings), At: time.Now().UTC()})
	}
	return r.store.ListSourceFindings(ctx, session.ID, db.SourceFindingFilter{})
}

func (r *Runner) runLevel(ctx context.Context, session models.Session, level []adapters.Adapter, targets []models.Target, scope *ScopeChecker, priorFindings []models.Finding, priorTechnologies []models.Technology, sourceFindings []models.SourceFinding, globalSem chan struct{}, toolSems map[string]chan struct{}) []adapterRunResult {
	results := make(chan adapterRunResult, len(level)*max(1, len(targets)))
	var wg sync.WaitGroup
	for _, adapter := range level {
		adapter := adapter
		for _, target := range targets {
			target := target
			input := adapters.AdapterInput{
				SessionID:         session.ID,
				Session:           session,
				Target:            target,
				PriorFindings:     append([]models.Finding(nil), priorFindings...),
				PriorTechnologies: append([]models.Technology(nil), priorTechnologies...),
				SourceFindings:    append([]models.SourceFinding(nil), sourceFindings...),
				ToolParameters:    session.ToolParameters[adapter.ID()],
				Scope:             scope,
				HTTPClient:        r.httpClient,
			}
			if !adapter.ShouldRun(input) {
				continue
			}
			if err := adapters.ValidateToolParameterValues(adapter.ID(), input.ToolParameters); err != nil {
				output := invalidToolParameterOutput(session, target, adapter, err)
				r.emit(ScanEvent{
					Type:      ScanEventToolError,
					SessionID: session.ID,
					TargetID:  target.ID,
					ToolID:    adapter.ID(),
					Phase:     string(adapter.Phase()),
					Status:    "failed",
					Message:   err.Error(),
					At:        time.Now().UTC(),
				})
				r.emit(ScanEvent{
					Type:       ScanEventToolCompleted,
					SessionID:  session.ID,
					TargetID:   target.ID,
					ToolID:     adapter.ID(),
					Phase:      string(adapter.Phase()),
					Status:     "failed",
					Message:    err.Error(),
					DurationMS: output.ToolRun.DurationMS,
					At:         time.Now().UTC(),
				})
				results <- adapterRunResult{output: output}
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := acquire(ctx, globalSem); err != nil {
					results <- adapterRunResult{ctxErr: err}
					return
				}
				defer release(globalSem)
				toolSem := toolSems[adapter.ID()]
				if err := acquire(ctx, toolSem); err != nil {
					results <- adapterRunResult{ctxErr: err}
					return
				}
				defer release(toolSem)
				if r.pause != nil {
					if err := r.pause.WaitIfPaused(ctx); err != nil {
						results <- adapterRunResult{ctxErr: err}
						return
					}
				}
				if r.options.ToolDelay > 0 {
					timer := time.NewTimer(r.options.ToolDelay)
					select {
					case <-ctx.Done():
						timer.Stop()
						results <- adapterRunResult{ctxErr: ctx.Err()}
						return
					case <-timer.C:
					}
				}
				runCtx := ctx
				var cancel context.CancelFunc
				if r.options.ToolTimeout > 0 {
					runCtx, cancel = context.WithTimeout(ctx, r.options.ToolTimeout)
					defer cancel()
				}
				r.emit(ScanEvent{
					Type:      ScanEventToolStarted,
					SessionID: session.ID,
					TargetID:  target.ID,
					ToolID:    adapter.ID(),
					Phase:     string(adapter.Phase()),
					Message:   adapter.Name() + " started",
					At:        time.Now().UTC(),
				})
				output, err := adapter.Run(runCtx, input)
				if err != nil {
					slog.Warn("adapter failed", "session_id", session.ID, "target_id", target.ID, "tool_id", adapter.ID(), "phase", adapter.Phase(), "error", err)
					r.emit(ScanEvent{
						Type:      ScanEventToolError,
						SessionID: session.ID,
						TargetID:  target.ID,
						ToolID:    adapter.ID(),
						Phase:     string(adapter.Phase()),
						Status:    "failed",
						Message:   err.Error(),
						At:        time.Now().UTC(),
					})
				}
				status := "completed"
				message := adapter.Name() + " completed"
				if err != nil {
					status = "failed"
					message = err.Error()
				}
				r.emit(ScanEvent{
					Type:         ScanEventToolCompleted,
					SessionID:    session.ID,
					TargetID:     target.ID,
					ToolID:       adapter.ID(),
					Phase:        string(adapter.Phase()),
					Status:       status,
					Message:      message,
					FindingCount: len(output.Findings),
					DurationMS:   output.ToolRun.DurationMS,
					At:           time.Now().UTC(),
				})
				var ctxErr error
				if runCtx.Err() != nil {
					ctxErr = runCtx.Err()
				}
				results <- adapterRunResult{output: output, ctxErr: ctxErr}
			}()
		}
	}
	wg.Wait()
	close(results)
	out := make([]adapterRunResult, 0, len(results))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func invalidToolParameterOutput(session models.Session, target models.Target, adapter adapters.Adapter, err error) adapters.AdapterOutput {
	now := time.Now().UTC()
	return adapters.AdapterOutput{ToolRun: models.ToolRun{
		ID:           models.NewID(),
		SessionID:    session.ID,
		TargetID:     target.ID,
		ToolID:       adapter.ID(),
		Args:         []string{},
		RawStderr:    "invalid tool parameters: " + err.Error(),
		ExitCode:     1,
		DurationMS:   0,
		NormalizedAt: &now,
		StartedAt:    now,
	}}
}

func acquire(ctx context.Context, sem chan struct{}) error {
	if sem == nil {
		return nil
	}
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release(sem chan struct{}) {
	if sem == nil {
		return
	}
	<-sem
}

func mergeTargets(existing []models.Target, updates []models.Target) []models.Target {
	for _, updated := range updates {
		found := false
		for i := range existing {
			if existing[i].ID == updated.ID {
				existing[i] = updated
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, updated)
		}
	}
	return existing
}

func (r *Runner) emit(event ScanEvent) {
	if r.onEvent == nil {
		return
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	r.onEvent(event)
}

func orderAdapters(scanAdapters []adapters.Adapter) ([]adapters.Adapter, error) {
	levels, err := adapterLevels(scanAdapters)
	if err != nil {
		return nil, err
	}
	var ordered []adapters.Adapter
	for _, level := range levels {
		ordered = append(ordered, level...)
	}
	return ordered, nil
}

func selectedAdapters(scanAdapters []adapters.Adapter, selectedTools, selectedPhases []string) ([]adapters.Adapter, error) {
	byID := make(map[string]adapters.Adapter, len(scanAdapters))
	for _, adapter := range scanAdapters {
		byID[adapter.ID()] = adapter
	}
	phaseSet := stringSet(selectedPhases)
	toolSet := stringSet(selectedTools)
	if len(toolSet) == 0 && len(phaseSet) == 0 {
		return scanAdapters, nil
	}
	include := map[string]bool{}
	if len(toolSet) > 0 {
		for id := range toolSet {
			adapter, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("unknown tool %q", id)
			}
			includeWithDependencies(adapter, byID, include)
		}
	} else {
		for _, adapter := range scanAdapters {
			include[adapter.ID()] = true
		}
	}
	var out []adapters.Adapter
	for _, adapter := range scanAdapters {
		if !include[adapter.ID()] {
			continue
		}
		if len(phaseSet) > 0 && !phaseSet[string(adapter.Phase())] {
			if len(toolSet) == 0 || !toolSet[adapter.ID()] {
				continue
			}
		}
		out = append(out, adapter)
	}
	return out, nil
}

func includeWithDependencies(adapter adapters.Adapter, byID map[string]adapters.Adapter, include map[string]bool) {
	if include[adapter.ID()] {
		return
	}
	include[adapter.ID()] = true
	for _, depID := range adapter.DependsOn() {
		if dep, ok := byID[depID]; ok {
			includeWithDependencies(dep, byID, include)
		}
	}
}

func stringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func adapterLevels(scanAdapters []adapters.Adapter) ([][]adapters.Adapter, error) {
	byID := make(map[string]adapters.Adapter, len(scanAdapters))
	order := make(map[string]int, len(scanAdapters))
	for index, adapter := range scanAdapters {
		byID[adapter.ID()] = adapter
		order[adapter.ID()] = index
	}
	dependents := map[string][]string{}
	remainingDeps := map[string]int{}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(adapter adapters.Adapter) error
	visit = func(adapter adapters.Adapter) error {
		id := adapter.ID()
		if visited[id] {
			return nil
		}
		if visiting[id] {
			return fmt.Errorf("adapter dependency cycle at %s", id)
		}
		visiting[id] = true
		for _, depID := range adapter.DependsOn() {
			dep, ok := byID[depID]
			if !ok {
				return fmt.Errorf("adapter %s depends on missing adapter %s", id, depID)
			}
			dependents[depID] = append(dependents[depID], id)
			remainingDeps[id]++
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for _, adapter := range scanAdapters {
		if err := visit(adapter); err != nil {
			return nil, err
		}
	}
	var ready []string
	for id := range byID {
		if remainingDeps[id] == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	var levels [][]adapters.Adapter
	for len(ready) > 0 {
		minRank := int(^uint(0) >> 1)
		for _, id := range ready {
			if rank := phaseRank(byID[id].Phase()); rank < minRank {
				minRank = rank
			}
		}
		var levelIDs []string
		var deferredReady []string
		for _, id := range ready {
			if phaseRank(byID[id].Phase()) == minRank {
				levelIDs = append(levelIDs, id)
			} else {
				deferredReady = append(deferredReady, id)
			}
		}
		ready = deferredReady
		sort.Slice(levelIDs, func(i, j int) bool {
			left := byID[levelIDs[i]]
			right := byID[levelIDs[j]]
			if left.Phase() == right.Phase() {
				return order[left.ID()] < order[right.ID()]
			}
			return left.Phase() < right.Phase()
		})
		level := make([]adapters.Adapter, 0, len(levelIDs))
		for _, id := range levelIDs {
			level = append(level, byID[id])
			for _, dependentID := range dependents[id] {
				remainingDeps[dependentID]--
				if remainingDeps[dependentID] == 0 {
					ready = append(ready, dependentID)
				}
			}
		}
		levels = append(levels, level)
	}
	if len(visited) != len(byID) {
		return nil, fmt.Errorf("adapter graph could not be fully scheduled")
	}
	return levels, nil
}

func phaseRank(phase adapters.Phase) int {
	switch phase {
	case adapters.PhaseRecon:
		return 0
	case adapters.PhaseFingerprint:
		return 1
	case adapters.PhaseEnumerate:
		return 2
	case adapters.PhaseVulnScan:
		return 3
	case adapters.PhaseCredential:
		return 4
	case adapters.PhaseOSINT:
		return 5
	case adapters.PhaseADDiscovery:
		return 6
	case adapters.PhaseADEnum:
		return 7
	case adapters.PhaseADPaths:
		return 8
	default:
		return 100
	}
}

func phaseName(level []adapters.Adapter) string {
	if len(level) == 0 {
		return "empty"
	}
	phase := string(level[0].Phase())
	for _, adapter := range level[1:] {
		if string(adapter.Phase()) != phase {
			return "mixed"
		}
	}
	return phase
}
