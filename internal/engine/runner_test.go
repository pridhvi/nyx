package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	nyxlog "github.com/pridhvi/nyx/internal/logging"
	"github.com/pridhvi/nyx/internal/models"
)

func TestRunnerTreatsAdapterErrorAsNonFatal(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	var logs bytes.Buffer
	if err := nyxlog.Configure(nyxlog.Options{Level: "warn", Format: "json", Output: &logs}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = nyxlog.Configure(nyxlog.Options{})
	})
	runner := NewRunnerWithAdapters(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id:  "nonfatal",
			err: errors.New("tool failed"),
			run: models.ToolRun{
				ID:        models.NewID(),
				SessionID: session.ID,
				ToolID:    "nonfatal",
				ExitCode:  1,
				RawStderr: "tool failed",
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
	if runs[0].StderrPath == "" {
		t.Fatalf("expected stderr sidecar path, got %#v", runs[0])
	}
	body, err := os.ReadFile(runs[0].StderrPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "tool failed" {
		t.Fatalf("expected stderr sidecar content, got %q", string(body))
	}
	if !strings.Contains(logs.String(), `"msg":"adapter failed"`) || !strings.Contains(logs.String(), `"tool_id":"nonfatal"`) {
		t.Fatalf("expected structured adapter failure log, got %q", logs.String())
	}
}

func TestRunnerPersistsPostScanLLMAnalysisToolRun(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected LLM path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-test",
			"object":"chat.completion",
			"created":1710000000,
			"model":"local-test",
			"choices":[{"index":0,"message":{"role":"assistant","content":"Post-scan analysis complete."},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14}
		}`))
	}))
	defer llmServer.Close()

	runner := NewRunnerWithOptions(store, nil, nil, RunnerOptions{
		GlobalConcurrency:  1,
		PerToolConcurrency: 1,
		LLMConfig: llmintel.Config{
			Provider:     "openai-compatible",
			BaseURL:      llmServer.URL + "/v1",
			Model:        "local-test",
			MaxTokens:    256,
			Temperature:  0.2,
			AllowedHosts: []string{"127.0.0.1"},
		},
	})

	if err := runner.Run(ctx, session); err != nil {
		t.Fatalf("runner failed: %v", err)
	}
	analyses, err := store.ListLLMAnalyses(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 || analyses[0].ModelID != "local-test" {
		t.Fatalf("expected persisted LLM analysis, got %#v", analyses)
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, run := range runs {
		if run.ToolID == "llm-analysis" {
			found = true
			if run.ExitCode != 0 || run.StdoutPath == "" {
				t.Fatalf("expected successful LLM tool run with stdout sidecar, got %#v", run)
			}
		}
	}
	if !found {
		t.Fatalf("expected llm-analysis tool run, got %#v", runs)
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
					RawStderr: ctx.Err().Error(),
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

func TestRunnerLeanModeDropsSidecarLogs(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "lean",
			run: models.ToolRun{
				ID:        models.NewID(),
				SessionID: session.ID,
				ToolID:    "lean",
				RawStdout: "large output",
				StartedAt: time.Now().UTC(),
			},
		},
	}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1, Lean: true})

	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected one tool run, got %#v", runs)
	}
	if runs[0].StdoutPath != "" || runs[0].StderrPath != "" {
		t.Fatalf("expected lean mode to persist empty log paths, got %#v", runs[0])
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(store.Path()), "runs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected lean mode to remove sidecar logs, got %d files", len(entries))
	}
}

func TestRunnerScopedHTTPClientRejectsOutOfScopeRedirect(t *testing.T) {
	ctx := context.Background()
	outOfScopeHit := atomic.Int32{}
	outOfScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outOfScopeHit.Add(1)
		_, _ = w.Write([]byte("outside"))
	}))
	defer outOfScope.Close()
	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScope.URL, http.StatusFound)
	}))
	defer inScope.Close()
	inScopeURL := strings.Replace(inScope.URL, "127.0.0.1", "localhost", 1)
	session, store := testRunnerStoreForURL(t, ctx, inScopeURL)
	defer store.Close()
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "http-client",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetTestURL(input.Target), nil)
				if err != nil {
					return adapters.AdapterOutput{}, err
				}
				_, err = input.HTTPClient.Do(req)
				stderr := ""
				exitCode := 0
				if err != nil {
					stderr = err.Error()
					exitCode = 1
				}
				return adapters.AdapterOutput{ToolRun: models.ToolRun{
					ID:        models.NewID(),
					SessionID: input.Session.ID,
					TargetID:  input.Target.ID,
					ToolID:    "http-client",
					RawStderr: stderr,
					ExitCode:  exitCode,
					StartedAt: time.Now().UTC(),
				}}, err
			},
		},
	}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1, ToolTimeout: time.Second})

	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if outOfScopeHit.Load() != 0 {
		t.Fatalf("expected redirect target to be blocked before request, got %d hits", outOfScopeHit.Load())
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected one tool run, got %#v", runs)
	}
	stderr, readErr := os.ReadFile(runs[0].StderrPath)
	if readErr != nil || !strings.Contains(string(stderr), "rejected by scope") {
		t.Fatalf("expected scoped redirect failure, got runs=%#v stderr=%q readErr=%v", runs, string(stderr), readErr)
	}
}

func TestRunnerHTTPClientIgnoresAmbientProxyAndHonorsExplicitProxy(t *testing.T) {
	ctx := context.Background()
	proxyHits := atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetURL := "http://" + closedListener.Addr().String()
	if err := closedListener.Close(); err != nil {
		t.Fatal(err)
	}

	session, store := testRunnerStoreForURL(t, ctx, targetURL)
	defer store.Close()
	runner := NewRunnerWithOptions(store, []adapters.Adapter{proxyProbeAdapter{}}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1, ToolTimeout: time.Second})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("expected ambient proxy to be ignored, got %d hits", proxyHits.Load())
	}

	session2, store2 := testRunnerStoreForURL(t, ctx, targetURL)
	defer store2.Close()
	runner = NewRunnerWithOptions(store2, []adapters.Adapter{proxyProbeAdapter{}}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1, ToolTimeout: time.Second, ProxyURL: proxy.URL})
	if err := runner.Run(ctx, session2); err != nil {
		t.Fatal(err)
	}
	if proxyHits.Load() != 1 {
		t.Fatalf("expected explicit proxy to be used once, got %d hits", proxyHits.Load())
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
	runner := NewRunnerWithOptions(store, nil, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1})
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

func TestAdapterLevelsPreservePhaseBarriersAndRegisteredOrder(t *testing.T) {
	levels, err := adapterLevels([]adapters.Adapter{
		fakeRunnerAdapter{id: "vuln-built-in", phase: adapters.PhaseVulnScan},
		fakeRunnerAdapter{id: "recon", phase: adapters.PhaseRecon},
		fakeRunnerAdapter{id: "enum", phase: adapters.PhaseEnumerate},
		fakeRunnerAdapter{id: "vuln-heavy", phase: adapters.PhaseVulnScan},
		fakeRunnerAdapter{id: "fingerprint", phase: adapters.PhaseFingerprint},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := adapterIDsByLevel(levels)
	want := [][]string{
		{"recon"},
		{"fingerprint"},
		{"enum"},
		{"vuln-built-in", "vuln-heavy"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("expected phase-barrier levels %v, got %v", want, got)
	}
}

func adapterIDsByLevel(levels [][]adapters.Adapter) [][]string {
	out := make([][]string, 0, len(levels))
	for _, level := range levels {
		ids := make([]string, 0, len(level))
		for _, adapter := range level {
			ids = append(ids, adapter.ID())
		}
		out = append(out, ids)
	}
	return out
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

func TestRunnerFiltersSelectedToolsAndPassesToolParameters(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	session.EnabledTools = []string{"sqlmap"}
	session.ToolParameters = map[string]map[string]any{
		"sqlmap": {"level": float64(3), "extra_args": []any{"--technique", "B"}},
	}
	ran := map[string]bool{}
	var selectedInput adapters.AdapterInput
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "dependency",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				ran["dependency"] = true
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "dependency", StartedAt: time.Now().UTC()}}, nil
			},
		},
		fakeRunnerAdapter{
			id:   "sqlmap",
			deps: []string{"dependency"},
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				ran["sqlmap"] = true
				selectedInput = input
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "sqlmap", StartedAt: time.Now().UTC()}}, nil
			},
		},
		fakeRunnerAdapter{
			id: "unselected",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				ran["unselected"] = true
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "unselected", StartedAt: time.Now().UTC()}}, nil
			},
		},
	}, nil, RunnerOptions{GlobalConcurrency: 2, PerToolConcurrency: 1})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if !ran["dependency"] || !ran["sqlmap"] || ran["unselected"] {
		t.Fatalf("unexpected selected tool execution: %#v", ran)
	}
	if selectedInput.ToolParameters["level"] != float64(3) {
		t.Fatalf("expected selected tool parameters, got %#v", selectedInput.ToolParameters)
	}
}

func TestRunnerRejectsInvalidPersistedToolParametersBeforeAdapterRun(t *testing.T) {
	ctx := context.Background()
	session, store := testRunnerStore(t, ctx)
	session.EnabledTools = []string{"sqlmap"}
	session.ToolParameters = map[string]map[string]any{
		"sqlmap": {"extra_args": []any{"--os-shell"}},
	}
	ran := false
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "sqlmap",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				ran = true
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "sqlmap", StartedAt: time.Now().UTC()}}, nil
			},
		},
	}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("expected adapter not to run with invalid persisted tool parameters")
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ToolID != "sqlmap" || runs[0].ExitCode == 0 {
		t.Fatalf("expected failed invalid-parameter tool run, got %#v", runs)
	}
	body, err := os.ReadFile(runs[0].StderrPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "invalid tool parameters") {
		t.Fatalf("expected invalid-parameter stderr sidecar, got %q", string(body))
	}
}

func TestRunnerRefreshesAuthProfileBetweenPhases(t *testing.T) {
	ctx := context.Background()
	var loginCount atomic.Int64
	var validToken atomic.Value
	validToken.Store("")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			token := fmt.Sprintf("s%d", loginCount.Add(1))
			validToken.Store(token)
			http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/"})
			_, _ = w.Write([]byte("ok"))
		case "/account":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != validToken.Load().(string) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Account"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	session, store := testRunnerStoreForURL(t, ctx, server.URL)
	session.ToolParameters = map[string]map[string]any{
		models.SessionScanOptionsKey: {
			"auth_profile": map[string]any{
				"type":                     "form",
				"login_url":                "/login",
				"username":                 "alice",
				"password":                 "secret",
				"validation_url":           "/account",
				"validation_contains":      "Account",
				"validate_each_phase":      true,
				"refresh_interval_seconds": 1,
			},
		},
	}
	var secondCookie string
	runner := NewRunnerWithOptions(store, []adapters.Adapter{
		fakeRunnerAdapter{
			id: "first",
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				validToken.Store("expired")
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "first", StartedAt: time.Now().UTC()}}, nil
			},
		},
		fakeRunnerAdapter{
			id:   "second",
			deps: []string{"first"},
			runFunc: func(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
				secondCookie = fmt.Sprint(input.Session.ToolParameters[models.SessionScanOptionsKey]["auth_cookie_header"])
				return adapters.AdapterOutput{ToolRun: models.ToolRun{ID: models.NewID(), SessionID: input.Session.ID, TargetID: input.Target.ID, ToolID: "second", StartedAt: time.Now().UTC()}}, nil
			},
		},
	}, nil, RunnerOptions{GlobalConcurrency: 1, PerToolConcurrency: 1})
	var events []ScanEvent
	runner.OnEvent(func(event ScanEvent) {
		events = append(events, event)
	})
	if err := runner.Run(ctx, session); err != nil {
		t.Fatal(err)
	}
	if loginCount.Load() < 2 {
		t.Fatalf("expected auth profile to be refreshed, got %d logins", loginCount.Load())
	}
	if !strings.Contains(secondCookie, "s2") {
		t.Fatalf("expected second phase to receive refreshed cookie, got %q", secondCookie)
	}
	if !sawAuthStatus(events, "invalid") || !sawAuthStatus(events, "refreshed") {
		t.Fatalf("expected invalid and refreshed auth events, got %#v", events)
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

type proxyProbeAdapter struct{}

func (proxyProbeAdapter) ID() string                           { return "proxy-probe" }
func (proxyProbeAdapter) Name() string                         { return "proxy-probe" }
func (proxyProbeAdapter) Phase() adapters.Phase                { return adapters.PhaseRecon }
func (proxyProbeAdapter) DependsOn() []string                  { return nil }
func (proxyProbeAdapter) ShouldRun(adapters.AdapterInput) bool { return true }
func (proxyProbeAdapter) Run(ctx context.Context, input adapters.AdapterInput) (adapters.AdapterOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetTestURL(input.Target), nil)
	if err == nil {
		_, err = input.HTTPClient.Do(req)
	}
	run := models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    "proxy-probe",
		StartedAt: time.Now().UTC(),
	}
	if err != nil {
		run.ExitCode = 1
		run.RawStderr = err.Error()
	}
	return adapters.AdapterOutput{ToolRun: run}, err
}

func targetTestURL(target models.Target) string {
	host := target.Host
	if target.Port > 0 {
		host = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	}
	return target.Protocol + "://" + host
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

func sawAuthStatus(events []ScanEvent, status string) bool {
	for _, event := range events {
		if event.Type == ScanEventAuthStatus && event.Status == status {
			return true
		}
	}
	return false
}

func testRunnerStore(t *testing.T, ctx context.Context) (models.Session, *db.Store) {
	t.Helper()
	return testRunnerStoreForURL(t, ctx, "https://example.com")
}

func testRunnerStoreForURL(t *testing.T, ctx context.Context, rawURL string) (models.Session, *db.Store) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(parsed.Port())
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Runner",
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: rawURL,
		InScope:     []string{parsed.Hostname()},
		CreatedAt:   time.Now().UTC(),
	}
	target := models.Target{
		ID:           models.NewID(),
		SessionID:    session.ID,
		Host:         parsed.Hostname(),
		Port:         port,
		Protocol:     parsed.Scheme,
		IsAlive:      true,
		DiscoveredBy: "test",
		CreatedAt:    time.Now().UTC(),
	}
	sessionDir := t.TempDir()
	_, err = db.CreateSessionDB(ctx, sessionDir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, sessionDir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	return session, store
}
