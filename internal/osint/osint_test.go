package osint

import (
	"context"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

func TestRunSeedsInScopeDomainsAndProviderStatus(t *testing.T) {
	ctx := context.Background()
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: "https://app.example.test", InScope: []string{"https://app.example.test"}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: "api.example.test", Port: 443, Protocol: "https", IsAlive: true, CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	findings, err := Run(ctx, store, session, RunRequest{Providers: []string{"github"}})
	if err != nil {
		t.Fatal(err)
	}
	var domain, provider bool
	for _, finding := range findings {
		if finding.Kind == "domain" && finding.Value == "app.example.test" {
			domain = true
		}
		if finding.Kind == "provider_status" && finding.Source == "github" {
			provider = true
		}
	}
	if !domain || !provider {
		t.Fatalf("expected domain and provider records, got %#v", findings)
	}
}
