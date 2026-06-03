package api

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
)

const scanEventHistoryLimit = 100

type scanEventBroker struct {
	mu          sync.Mutex
	history     map[string][]engine.ScanEvent
	subscribers map[string]map[chan engine.ScanEvent]struct{}
}

func newScanEventBroker() *scanEventBroker {
	return &scanEventBroker{
		history:     make(map[string][]engine.ScanEvent),
		subscribers: make(map[string]map[chan engine.ScanEvent]struct{}),
	}
}

func (b *scanEventBroker) publish(event engine.ScanEvent) {
	if event.SessionID == "" {
		return
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	b.mu.Lock()
	events := append(b.history[event.SessionID], event)
	if len(events) > scanEventHistoryLimit {
		events = events[len(events)-scanEventHistoryLimit:]
	}
	b.history[event.SessionID] = events
	for ch := range b.subscribers[event.SessionID] {
		select {
		case ch <- event:
		default:
		}
	}
	b.mu.Unlock()
}

func (b *scanEventBroker) subscribe(sessionID string) (<-chan engine.ScanEvent, func()) {
	b.mu.Lock()
	history := append([]engine.ScanEvent(nil), b.history[sessionID]...)
	ch := make(chan engine.ScanEvent, len(history)+32)
	if b.subscribers[sessionID] == nil {
		b.subscribers[sessionID] = make(map[chan engine.ScanEvent]struct{})
	}
	b.subscribers[sessionID][ch] = struct{}{}
	b.mu.Unlock()

	for _, event := range history {
		ch <- event
	}

	cancel := func() {
		b.mu.Lock()
		delete(b.subscribers[sessionID], ch)
		if len(b.subscribers[sessionID]) == 0 {
			delete(b.subscribers, sessionID)
		}
		close(ch)
		b.mu.Unlock()
	}
	return ch, cancel
}

func (b *scanEventBroker) snapshot(sessionID string) []engine.ScanEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]engine.ScanEvent(nil), b.history[sessionID]...)
}

var scanEventUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) scanEvents(w http.ResponseWriter, r *http.Request) {
	if websocketCrossOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-origin websocket requests are not allowed"))
		return
	}
	sessionID := r.PathValue("id")
	if _, err := dbSessionExists(r, s.cfg.SessionDir, sessionID); err != nil {
		writeDBError(w, err)
		return
	}
	conn, err := scanEventUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	events, unsubscribe := s.scanManager.Subscribe(sessionID)
	defer unsubscribe()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := conn.WriteJSON(event); err != nil {
				return
			}
		}
	}
}

func dbSessionExists(r *http.Request, sessionDir, sessionID string) (bool, error) {
	store, err := db.OpenSession(r.Context(), sessionDir, sessionID)
	if err != nil {
		return false, err
	}
	defer store.Close()
	_, err = store.GetSession(r.Context())
	if err != nil {
		return false, err
	}
	return true, nil
}
