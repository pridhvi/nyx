package api

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	appconfig "github.com/pridhvi/nyx/internal/config"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
)

type ScanManager struct {
	sessionDir      string
	httpClient      adapters.HTTPDoer
	appConfig       appconfig.Config
	llmAllowedHosts []string
	events          *scanEventBroker
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	mu              sync.Mutex
	running         map[string]context.CancelFunc
	paused          map[string]bool
	resumeCh        map[string]chan struct{}
	shuttingDown    bool
	plugins         func() []models.PluginRecord
}

func NewScanManager(sessionDir string, httpClient adapters.HTTPDoer, appConfig appconfig.Config, llmAllowedHosts []string) *ScanManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanManager{
		sessionDir:      sessionDir,
		httpClient:      httpClient,
		appConfig:       appConfig,
		llmAllowedHosts: append([]string(nil), llmAllowedHosts...),
		events:          newScanEventBroker(),
		ctx:             ctx,
		cancel:          cancel,
		running:         make(map[string]context.CancelFunc),
		paused:          make(map[string]bool),
		resumeCh:        make(map[string]chan struct{}),
	}
}

func (m *ScanManager) SetPluginProvider(provider func() []models.PluginRecord) {
	m.plugins = provider
}

func (m *ScanManager) Start(session models.Session) {
	ctx, cancel := context.WithCancel(m.ctx)
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		cancel()
		completed := time.Now().UTC()
		m.updateSessionStatus(session.ID, models.SessionStatusCancelled, nil, &completed)
		m.Publish(engine.ScanEvent{
			Type:      engine.ScanEventCancelled,
			SessionID: session.ID,
			Status:    string(models.SessionStatusCancelled),
			Message:   "Scan was not started because the server is shutting down",
			At:        completed,
		})
		return
	}
	m.running[session.ID] = cancel
	m.wg.Add(1)
	m.mu.Unlock()
	m.Publish(engine.ScanEvent{
		Type:      engine.ScanEventQueued,
		SessionID: session.ID,
		Status:    string(session.Status),
		Message:   "Scan queued",
		At:        time.Now().UTC(),
	})
	go func() {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			delete(m.running, session.ID)
			delete(m.paused, session.ID)
			delete(m.resumeCh, session.ID)
			m.mu.Unlock()
			cancel()
		}()
		store, err := db.OpenSession(ctx, m.sessionDir, session.ID)
		if err != nil {
			slog.Error("open async scan session", "session_id", session.ID, "error", err)
			m.Publish(engine.ScanEvent{
				Type:      engine.ScanEventFailed,
				SessionID: session.ID,
				Status:    string(models.SessionStatusFailed),
				Message:   err.Error(),
				At:        time.Now().UTC(),
			})
			return
		}
		defer store.Close()
		if err := m.runSession(ctx, store, session); err != nil {
			slog.Error("async scan failed", "session_id", session.ID, "error", err)
		}
	}()
}

func (m *ScanManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.shuttingDown {
		m.shuttingDown = true
		m.cancel()
	}
	for _, cancel := range m.running {
		cancel()
	}
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *ScanManager) runSession(ctx context.Context, store *db.Store, session models.Session) error {
	switch session.WorkloadMode {
	case models.WorkloadModeStatic:
		llmConfig := llmintel.ConfigFromSessionWithApp(session, m.appConfig)
		llmConfig.AllowedHosts = m.llmAllowedHosts
		audit := engine.NewAuditRunner(store, engine.AuditOptions{
			Tools:     session.EnabledTools,
			LLMConfig: llmConfig,
		})
		audit.OnEvent(m.Publish)
		return audit.Run(ctx, session, session.SourcePath)
	case models.WorkloadModeCombined:
		llmConfig := llmintel.ConfigFromSessionWithApp(session, m.appConfig)
		llmConfig.AllowedHosts = m.llmAllowedHosts
		audit := engine.NewAuditRunner(store, engine.AuditOptions{
			Tools:           auditTools(session.EnabledTools),
			KeepSessionOpen: true,
			LLMConfig:       llmConfig,
		})
		audit.OnEvent(m.Publish)
		if err := audit.Run(ctx, session, session.SourcePath); err != nil {
			return err
		}
		m.Publish(engine.ScanEvent{Type: engine.ScanEventPhaseStarted, SessionID: session.ID, Phase: "dynamic", Message: "Dynamic scan started", At: time.Now().UTC()})
		dynamicErr := m.runDynamic(ctx, store, session)
		m.Publish(engine.ScanEvent{Type: engine.ScanEventPhaseCompleted, SessionID: session.ID, Phase: "dynamic", Message: "Dynamic scan completed", At: time.Now().UTC()})
		return dynamicErr
	default:
		return m.runDynamic(ctx, store, session)
	}
}

func (m *ScanManager) runDynamic(ctx context.Context, store *db.Store, session models.Session) error {
	session.EnabledTools = dynamicTools(session.EnabledTools)
	options := runnerOptionsFromSession(session)
	options.LLMAllowedHosts = m.llmAllowedHosts
	options.LLMConfig = llmintel.ConfigFromSessionWithApp(session, m.appConfig)
	options.LLMConfig.AllowedHosts = m.llmAllowedHosts
	runner := engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), m.httpClient, options)
	runner.SetPauseController(m.pauseController(session.ID))
	for _, plugin := range m.enabledPlugins() {
		runner.AddAdapters(adapters.NewConfiguredPlugin(plugin))
	}
	runner.OnEvent(m.Publish)
	return runner.Run(ctx, session)
}

func auditTools(tools []string) []string {
	var out []string
	for _, tool := range tools {
		if strings.HasPrefix(strings.TrimSpace(tool), "audit/") {
			out = append(out, tool)
		}
	}
	return out
}

func dynamicTools(tools []string) []string {
	var out []string
	for _, tool := range tools {
		if !strings.HasPrefix(strings.TrimSpace(tool), "audit/") {
			out = append(out, tool)
		}
	}
	return out
}

func (m *ScanManager) Pause(sessionID string) bool {
	m.mu.Lock()
	if _, ok := m.running[sessionID]; !ok {
		m.mu.Unlock()
		return false
	}
	if m.resumeCh[sessionID] == nil {
		m.resumeCh[sessionID] = make(chan struct{})
	}
	m.paused[sessionID] = true
	m.mu.Unlock()
	m.updateSessionStatus(sessionID, models.SessionStatusPaused, nil, nil)
	m.Publish(engine.ScanEvent{Type: engine.ScanEventRunning, SessionID: sessionID, Status: "paused", Message: "Scan paused", At: time.Now().UTC()})
	return true
}

func (m *ScanManager) Resume(sessionID string) bool {
	m.mu.Lock()
	if _, ok := m.running[sessionID]; !ok {
		m.mu.Unlock()
		return false
	}
	if ch := m.resumeCh[sessionID]; ch != nil {
		close(ch)
	}
	m.resumeCh[sessionID] = make(chan struct{})
	m.paused[sessionID] = false
	m.mu.Unlock()
	m.updateSessionStatus(sessionID, models.SessionStatusRunning, nil, nil)
	m.Publish(engine.ScanEvent{Type: engine.ScanEventRunning, SessionID: sessionID, Status: "running", Message: "Scan resumed", At: time.Now().UTC()})
	return true
}

func (m *ScanManager) pauseController(sessionID string) pauseControllerFunc {
	return func(ctx context.Context) error {
		for {
			m.mu.Lock()
			paused := m.paused[sessionID]
			ch := m.resumeCh[sessionID]
			if ch == nil {
				ch = make(chan struct{})
				m.resumeCh[sessionID] = ch
			}
			m.mu.Unlock()
			if !paused {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ch:
			}
		}
	}
}

type pauseControllerFunc func(context.Context) error

func (f pauseControllerFunc) WaitIfPaused(ctx context.Context) error { return f(ctx) }

func (m *ScanManager) enabledPlugins() []models.PluginRecord {
	if m.plugins == nil {
		return nil
	}
	var out []models.PluginRecord
	for _, plugin := range m.plugins() {
		if plugin.Enabled {
			out = append(out, plugin)
		}
	}
	return out
}

func (m *ScanManager) Stop(sessionID string) bool {
	m.mu.Lock()
	cancel, ok := m.running[sessionID]
	m.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	m.Publish(engine.ScanEvent{
		Type:      engine.ScanEventFailed,
		SessionID: sessionID,
		Status:    string(models.SessionStatusCancelled),
		Message:   "Scan cancellation requested",
		At:        time.Now().UTC(),
	})
	return true
}

func (m *ScanManager) updateSessionStatus(sessionID string, status models.SessionStatus, startedAt, completedAt *time.Time) {
	store, err := db.OpenSession(context.Background(), m.sessionDir, sessionID)
	if err != nil {
		return
	}
	defer store.Close()
	_ = store.UpdateSessionStatus(context.Background(), sessionID, status, startedAt, completedAt)
}

func (m *ScanManager) Publish(event engine.ScanEvent) {
	m.events.publish(event)
}

func runnerOptionsFromSession(session models.Session) engine.RunnerOptions {
	options := session.RunnerOptions
	return engine.RunnerOptions{
		GlobalConcurrency:  options.Concurrency,
		PerToolConcurrency: options.PerToolConcurrency,
		ToolDelay:          time.Duration(options.ToolDelayMS) * time.Millisecond,
		ToolTimeout:        time.Duration(options.ToolTimeoutSeconds) * time.Second,
		ProxyURL:           options.ProxyURL,
	}
}

func (m *ScanManager) Subscribe(sessionID string) (<-chan engine.ScanEvent, func()) {
	return m.events.subscribe(sessionID)
}

func (m *ScanManager) EventHistory(sessionID string) []engine.ScanEvent {
	return m.events.snapshot(sessionID)
}
