package engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

type Runner struct {
	store      *db.Store
	adapters   []adapters.Adapter
	httpClient adapters.HTTPDoer
}

func NewRunner(store *db.Store) *Runner {
	return &Runner{
		store:      store,
		adapters:   DefaultSafeAdapters(),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func DefaultSafeAdapters() []adapters.Adapter {
	return []adapters.Adapter{
		adapters.NewHTTPProbe(),
		adapters.NewSecurityHeaders(),
	}
}

func NewRunnerWithHTTPClient(store *db.Store, client adapters.HTTPDoer) *Runner {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Runner{store: store, adapters: DefaultSafeAdapters(), httpClient: client}
}

func NewRunnerWithAdapters(store *db.Store, scanAdapters []adapters.Adapter, client adapters.HTTPDoer) *Runner {
	return &Runner{store: store, adapters: scanAdapters, httpClient: client}
}

func (r *Runner) Run(ctx context.Context, session models.Session) error {
	started := time.Now().UTC()
	if err := r.store.UpdateSessionStatus(ctx, session.ID, models.SessionStatusRunning, &started, nil); err != nil {
		return err
	}
	targets, err := r.store.ListTargets(ctx, session.ID)
	if err != nil {
		return err
	}
	scope, err := NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return err
	}
	ordered, err := orderAdapters(r.adapters)
	if err != nil {
		return err
	}
	var scanErr error
	for _, adapter := range ordered {
		for _, target := range targets {
			input := adapters.AdapterInput{
				SessionID:  session.ID,
				Session:    session,
				Target:     target,
				Scope:      scope,
				HTTPClient: r.httpClient,
			}
			if !adapter.ShouldRun(input) {
				continue
			}
			output, err := adapter.Run(ctx, input)
			if err != nil && scanErr == nil {
				scanErr = err
			}
			if persistErr := r.persist(ctx, session.ID, output); persistErr != nil {
				scanErr = persistErr
			}
			for _, updated := range output.NewTargets {
				for i := range targets {
					if targets[i].ID == updated.ID {
						targets[i] = updated
						break
					}
				}
			}
		}
	}
	if err := r.store.UpdateSessionCounts(ctx, session.ID); err != nil {
		return err
	}
	completed := time.Now().UTC()
	status := models.SessionStatusCompleted
	if scanErr != nil {
		status = models.SessionStatusFailed
	}
	if err := r.store.UpdateSessionStatus(ctx, session.ID, status, nil, &completed); err != nil {
		return err
	}
	return scanErr
}

func (r *Runner) persist(ctx context.Context, sessionID string, output adapters.AdapterOutput) error {
	for _, target := range output.NewTargets {
		if err := r.store.UpdateTarget(ctx, target); err != nil {
			return err
		}
	}
	for _, finding := range output.Findings {
		if err := r.store.InsertFinding(ctx, finding); err != nil {
			return err
		}
	}
	if output.ToolRun.ID != "" {
		if err := r.store.InsertToolRun(ctx, output.ToolRun); err != nil {
			return err
		}
	}
	return r.store.UpdateSessionCounts(ctx, sessionID)
}

func orderAdapters(scanAdapters []adapters.Adapter) ([]adapters.Adapter, error) {
	byID := make(map[string]adapters.Adapter, len(scanAdapters))
	for _, adapter := range scanAdapters {
		byID[adapter.ID()] = adapter
	}
	var ordered []adapters.Adapter
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
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		ordered = append(ordered, adapter)
		return nil
	}
	for _, adapter := range scanAdapters {
		if err := visit(adapter); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}
