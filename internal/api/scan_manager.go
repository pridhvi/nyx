package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

type ScanManager struct {
	sessionDir string
	httpClient adapters.HTTPDoer
	events     *scanEventBroker
	mu         sync.Mutex
	running    map[string]context.CancelFunc
}

func NewScanManager(sessionDir string, httpClient adapters.HTTPDoer) *ScanManager {
	return &ScanManager{
		sessionDir: sessionDir,
		httpClient: httpClient,
		events:     newScanEventBroker(),
		running:    make(map[string]context.CancelFunc),
	}
}

func (m *ScanManager) Start(session models.Session) {
	m.Publish(engine.ScanEvent{
		Type:      engine.ScanEventQueued,
		SessionID: session.ID,
		Status:    string(session.Status),
		Message:   "Scan queued",
		At:        time.Now().UTC(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.running[session.ID] = cancel
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.running, session.ID)
			m.mu.Unlock()
			cancel()
		}()
		store, err := db.OpenSession(context.Background(), m.sessionDir, session.ID)
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
		runner := engine.NewRunnerWithHTTPClient(store, m.httpClient)
		runner.OnEvent(m.Publish)
		if err := runner.Run(ctx, session); err != nil {
			slog.Error("async scan failed", "session_id", session.ID, "error", err)
		}
	}()
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

func (m *ScanManager) Publish(event engine.ScanEvent) {
	m.events.publish(event)
}

func (m *ScanManager) Subscribe(sessionID string) (<-chan engine.ScanEvent, func()) {
	return m.events.subscribe(sessionID)
}
