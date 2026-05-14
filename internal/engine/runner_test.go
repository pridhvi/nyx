package engine

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

func TestRunnerTreatsAdapterErrorAsNonFatal(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	runner := NewRunnerWithAdapters(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id:  "nonfatal",
			err: errors.New("tool failed"),
			run: models.ToolRun{
				ID:        models.NewID(),
				SessionID: session.ID,
				ToolID:    "nonfatal",
				ExitCode:  1,
				StderrRaw: "tool failed",
				StartedAt: time.Now().UTC(),
			},
		},
	}, nil)

	if err := runner.Run(ctx, session); err != nil {
		t.Fatalf("expected adapter error to be non-fatal, got %v", err)
	}
	got, err := store.GetSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SessionStatusCompleted {
		t.Fatalf("expected completed session, got %s", got.Status)
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ExitCode != 1 {
		t.Fatalf("expected failed tool run to persist, got %#v", runs)
	}
}

func TestRunnerCancellationSetsCancelledStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session, store := testRunnerStore(t, context.Background())
	entered := make(chan struct{})
	runner := NewRunnerWithAdapters(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "blocking",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				close(entered)
				<-ctx.Done()
				return adapters.AdapterOutput{ToolRun: models.ToolRun{
					ID:        models.NewID(),
					SessionID: input.Session.ID,
					ToolID:    "blocking",
					ExitCode:  1,
					StderrRaw: ctx.Err().Error(),
					StartedAt: time.Now().UTC(),
				}}, ctx.Err()
			},
		},
	}, nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, session)
	}()
	<-entered
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	got, err := store.GetSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SessionStatusCancelled {
		t.Fatalf("expected cancelled session, got %s", got.Status)
	}
}

func TestRunnerLoadsConfiguredPlugins(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	now := time.Now().UTC()
	if err := store.UpsertPlugin(ctx, models.PluginRecord{
		ID:        models.NewID(),
		Name:      "missing-fixture",
		Binary:    filepath.Join(t.TempDir(), "missing-plugin"),
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	runner := NewRunnerWithHTTPClient(store, nil)
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.ToolID == "plugin:missing-fixture" && run.ExitCode != 0 {
			return
		}
	}
	t.Fatalf("expected failed configured plugin tool run, got %#v", runs)
}

func TestAdapterLevelsDetectDependencyErrors(t *testing.T) {
	_, err := adapterLevels([]adapters.Adapter{
		fakeRunnerAdapter{id: "dependent", deps: []string{"missing"}},
	})
	if err == nil {
		t.Fatal("expected missing dependency error")
	}
	_, err = adapterLevels([]adapters.Adapter{
		fakeRunnerAdapter{id: "a", deps: []string{"b"}},
		fakeRunnerAdapter{id: "b", deps: []string{"a"}},
	})
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestRunnerRunsSameLevelAdaptersInParallel(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	entered := make(chan string, 2)
	release := make(chan struct{})
	runFunc := func(id string) func(context.Context, adapters.AdapterInput) (adapters.AdapterOutput, error) {
		return func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
			entered <- id
			select {
			case <-ctx.Done():
				return adapters.AdapterOutput{}, ctx.Err()
			case <-release:
			}
			return adapters.AdapterOutput{ToolRun: models.ToolRun{
				ID:        models.NewID(),
				SessionID: input.Session.ID,
				TargetID:  input.Target.ID,
				ToolID:    id,
				StartedAt: time.Now().UTC(),
			}}, nil
		}
	}
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{id: "parallel-a", runFunc: runFunc("parallel-a")},
		fakeRunnerAdapter{id: "parallel-b", runFunc: runFunc("parallel-b")},
	}, nil, RunnerOptions{GlobalConcurrency: 2, PerToolConcurrency: 1})
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, session)
	}()
	seen := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(seen) < 2 {
		select {
		case id := <-entered:
			seen[id] = true
		case <-deadline:
			t.Fatalf("expected both same-level adapters to enter before release, saw %#v", seen)
		}
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestRunnerPerToolSemaphoreLimitsTargetConcurrency(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	if err := store.InsertTarget(ctx, models.Target{
		ID:           models.NewID(),
		SessionID:    session.ID,
		Host:         "example.com",
		Port:         8443,
		Protocol:     "https",
		IsAlive:      true,
		DiscoveredBy: "test",
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	sleep := 80 * time.Millisecond
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{id: "serialized", sleep: sleep},
	}, nil, RunnerOptions{GlobalConcurrency: 2, PerToolConcurrency: 1})
	started := time.Now()
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < sleep*2 {
		t.Fatalf("expected per-tool semaphore to serialize two targets for at least %s, got %s", sleep*2, elapsed)
	}
}

func TestRunnerPropagatesPriorFindingsAndTechnologies(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	var sawPrior atomic.Bool
	first := fakeRunnerAdapter{
		id: "first",
		output: adapters.AdapterOutput{
			Findings: []models.Finding{{
				ID:                 models.NewID(),
				SessionID:          session.ID,
				TargetID:           "",
				ToolID:             "first",
				Type:               models.FindingTypeInfo,
				Severity:           models.SeverityInfo,
				Confidence:         0.5,
				Title:              "first finding",
				EvidenceNormalized: "{}",
				Tags:               []string{"test"},
				CreatedAt:          time.Now().UTC(),
			}},
			Technologies: []models.Technology{{
				ID:         models.NewID(),
				Name:       "first-tech",
				Category:   "test",
				Confidence: 0.5,
				SourceTool: "first",
			}},
		},
	}
	second := fakeRunnerAdapter{
		id:   "second",
		deps: []string{"first"},
		runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
			if len(input.PriorFindings) > 0 && len(input.PriorTechnologies) > 0 {
				sawPrior.Store(true)
			}
			return adapters.AdapterOutput{ToolRun: models.ToolRun{
				ID:        models.NewID(),
				SessionID: input.Session.ID,
				TargetID:  input.Target.ID,
				ToolID:    "second",
				StartedAt: time.Now().UTC(),
			}}, nil
		},
	}
	runner := NewRunnerWithOptions(store, []adapters.Adapter{second, first}, nil, RunnerOptions{GlobalConcurrency: 2, PerToolConcurrency: 1})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if !sawPrior.Load() {
		t.Fatal("expected dependent adapter to receive accumulated findings and technologies")
	}
}

type fakeRunnerAdapter struct {
	id      string
	err     error
	run     models.ToolRun
	output  adapters.AdapterOutput
	phase   adapters.Phase
	deps    []string
	sleep   time.Duration
	runFunc func(context.Context, adapters.AdapterInput) (adapters.AdapterOutput, error)
}

func (a fakeRunnerAdapter) ID() string { return a.id }

func (a fakeRunnerAdapter) Name() string { return a.id }

func (a fakeRunnerAdapter) Phase() adapters.Phase {
	if a.phase != "" {
		return a.phase
	}
	return adapters.PhaseRecon
}

func (a fakeRunnerAdapter) DependsOn() []string { return a.deps }

func (a fakeRunnerAdapter) ShouldRun(adapters.AdapterInput) bool { return true }

func (a fakeRunnerAdapter) Run(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
	if a.runFunc != nil {
		return a.runFunc(ctx, input)
	}
	if a.sleep > 0 {
		select {
		case <-ctx.Done():
			return adapters.AdapterOutput{}, ctx.Err()
		case <-time.After(a.sleep):
		}
	}
	if a.output.ToolRun.ID != "" || len(a.output.Findings) > 0 || len(a.output.NewTargets) > 0 || len(a.output.Technologies) > 0 {
		output := a.output
		if output.ToolRun.ID == "" {
			output.ToolRun = models.ToolRun{
				ID:        models.NewID(),
				SessionID: input.Session.ID,
				TargetID:  input.Target.ID,
				ToolID:    a.id,
				StartedAt: time.Now().UTC(),
			}
		}
		for i := range output.Findings {
			if output.Findings[i].TargetID == "" {
				output.Findings[i].TargetID = input.Target.ID
			}
		}
		for i := range output.Technologies {
			if output.Technologies[i].TargetID == "" {
				output.Technologies[i].TargetID = input.Target.ID
			}
		}
		return output, a.err
	}
	run := a.run
	if run.SessionID == "" {
		run.SessionID = input.Session.ID
	}
	if run.TargetID == "" {
		run.TargetID = input.Target.ID
	}
	return adapters.AdapterOutput{ToolRun: run}, a.err
}

func testRunnerStore(t *testing.T, ctx context.Context) (models.Session, *db.Store) {
	t.Helper()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Runner",
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"example.com"},
		CreatedAt:   time.Now().UTC(),
	}
	target := models.Target{
		ID:           models.NewID(),
		SessionID:    session.ID,
		Host:         "example.com",
		Port:         443,
		Protocol:     "https",
		IsAlive:      true,
		DiscoveredBy: "test",
		CreatedAt:    time.Now().UTC(),
	}
	record, err := db.CreateSessionDB(ctx, t.TempDir(), session, target)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, filepath.Dir(record.DBPath), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	return session, store
}
