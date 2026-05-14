package adapters

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kanini/nox/internal/models"
)

func TestHTTPAdaptersRejectOutOfScopeBeforeNetwork(t *testing.T) {
	session := models.Session{
		ID:        "session-1",
		Mode:      models.ScanModeActive,
		CreatedAt: time.Now().UTC(),
	}
	target := models.Target{
		ID:        "target-1",
		SessionID: session.ID,
		Host:      "blocked.example.com",
		Protocol:  "https",
		Port:      443,
		IsAlive:   true,
	}

	for _, adapter := range []Adapter{NewHTTPProbe(), NewSecurityHeaders()} {
		t.Run(adapter.ID(), func(t *testing.T) {
			client := &countingHTTPClient{}
			output, err := adapter.Run(context.Background(), AdapterInput{
				SessionID:  session.ID,
				Session:    session,
				Target:     target,
				Scope:      rejectingScope{},
				HTTPClient: client,
			})
			if err == nil {
				t.Fatal("expected scope error")
			}
			if client.calls != 0 {
				t.Fatalf("expected no network calls, got %d", client.calls)
			}
			if output.ToolRun.ID == "" || output.ToolRun.ExitCode == 0 || output.ToolRun.StderrRaw == "" {
				t.Fatalf("expected failed tool run for scope rejection, got %#v", output.ToolRun)
			}
		})
	}
}

type rejectingScope struct{}

func (rejectingScope) IsInScope(string) (bool, string) {
	return false, "blocked by test scope"
}

type countingHTTPClient struct {
	calls int
}

func (c *countingHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, context.Canceled
}
