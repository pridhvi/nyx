package engine

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/kanini/nox/internal/adapters"
	cveintel "github.com/kanini/nox/internal/cve"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

type Runner struct {
	store      *db.Store
	adapters   []adapters.Adapter
	httpClient adapters.HTTPDoer
	onEvent    ScanEventHandler
	options    RunnerOptions
}

type RunnerOptions struct {
	GlobalConcurrency  int
	PerToolConcurrency int
	ToolDelay          time.Duration
	ToolTimeout        time.Duration
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
		adapters.NewNmap(),
		adapters.NewFFUF(),
		adapters.NewNucleiVuln(),
		adapters.NewSSRFMap(),
		adapters.NewJWTTool(),
		adapters.NewOAuthCheck(),
		adapters.NewSSTICheck(),
		adapters.NewXXEFuzz(),
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
	return &Runner{store: store, adapters: scanAdapters, httpClient: client, options: normalizeRunnerOptions(options)}
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
	levels, err := adapterLevels(r.adapters)
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
	for _, adapter := range r.adapters {
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
		r.emit(ScanEvent{
			Type:      ScanEventPhaseStarted,
			SessionID: session.ID,
			Phase:     phaseName,
			Message:   fmt.Sprintf("Phase %s started", phaseName),
			At:        time.Now().UTC(),
		})
		results := r.runLevel(ctx, session, level, targets, scope, priorFindings, priorTechnologies, globalSem, toolSems)
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
		if cveErr := r.runCVECorrelation(finalCtx, session); cveErr != nil {
			scanErr = cveErr
		}
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
		if err := r.store.InsertToolRun(ctx, output.ToolRun); err != nil {
			return err
		}
	}
	return r.store.UpdateSessionCounts(ctx, sessionID)
}

type adapterRunResult struct {
	output adapters.AdapterOutput
	ctxErr error
}

func (r *Runner) runLevel(ctx context.Context, session models.Session, level []adapters.Adapter, targets []models.Target, scope *ScopeChecker, priorFindings []models.Finding, priorTechnologies []models.Technology, globalSem chan struct{}, toolSems map[string]chan struct{}) []adapterRunResult {
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
				Scope:             scope,
				HTTPClient:        r.httpClient,
			}
			if !adapter.ShouldRun(input) {
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

func adapterLevels(scanAdapters []adapters.Adapter) ([][]adapters.Adapter, error) {
	byID := make(map[string]adapters.Adapter, len(scanAdapters))
	for _, adapter := range scanAdapters {
		byID[adapter.ID()] = adapter
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
		levelIDs := ready
		ready = nil
		sort.Slice(levelIDs, func(i, j int) bool {
			left := byID[levelIDs[i]]
			right := byID[levelIDs[j]]
			if left.Phase() == right.Phase() {
				return left.ID() < right.ID()
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
