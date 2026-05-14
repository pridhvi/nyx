package engine

import (
	"context"
	"errors"
	"path/filepath"
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

type fakeRunnerAdapter struct {
	id      string
	err     error
	run     models.ToolRun
	runFunc func(context.Context, adapters.AdapterInput) (adapters.AdapterOutput, error)
}

func (a fakeRunnerAdapter) ID() string { return a.id }

func (a fakeRunnerAdapter) Name() string { return a.id }

func (a fakeRunnerAdapter) Phase() adapters.Phase { return adapters.PhaseRecon }

func (a fakeRunnerAdapter) DependsOn() []string { return nil }

func (a fakeRunnerAdapter) ShouldRun(adapters.AdapterInput) bool { return true }

func (a fakeRunnerAdapter) Run(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
	if a.runFunc != nil {
		return a.runFunc(ctx, input)
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
