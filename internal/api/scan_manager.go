package api

import (
	"context"
	"log/slog"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

type ScanManager struct {
	sessionDir string
	httpClient adapters.HTTPDoer
}

func NewScanManager(sessionDir string, httpClient adapters.HTTPDoer) *ScanManager {
	return &ScanManager{sessionDir: sessionDir, httpClient: httpClient}
}

func (m *ScanManager) Start(session models.Session) {
	go func() {
		store, err := db.OpenSession(context.Background(), m.sessionDir, session.ID)
		if err != nil {
			slog.Error("open async scan session", "session_id", session.ID, "error", err)
			return
		}
		defer store.Close()
		runner := engine.NewRunnerWithHTTPClient(store, m.httpClient)
		if err := runner.Run(context.Background(), session); err != nil {
			slog.Error("async scan failed", "session_id", session.ID, "error", err)
		}
	}()
}
