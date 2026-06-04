package poc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func TestRunRequiresExplicitConfirmation(t *testing.T) {
	ctx := context.Background()
	store, session, finding := pocTestStore(t, "Reflected XSS")
	defer store.Close()
	if _, err := Run(ctx, store, session.ID, finding.ID, RunRequest{}); err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Fatalf("expected confirmation error, got %v", err)
	}
	results, err := store.ListPoCResults(ctx, session.ID, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no persisted result without confirmation, got %#v", results)
	}
}

func TestRunPersistsSafeManualResult(t *testing.T) {
	ctx := context.Background()
	store, session, finding := pocTestStore(t, "Open redirect")
	defer store.Close()
	payload := models.Payload{
		ID:          "payload-1",
		SessionID:   session.ID,
		FindingID:   finding.ID,
		PayloadType: "redirect",
		Payload:     "https://example.net/",
		Context:     "test",
		Confidence:  0.5,
		Rank:        1,
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertPayload(ctx, payload); err != nil {
		t.Fatal(err)
	}
	result, err := Run(ctx, store, session.ID, finding.ID, RunRequest{Confirm: true, PayloadID: "payload-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.PoCStatusInconclusive || result.PayloadID != "payload-1" || result.TargetID != finding.TargetID {
		t.Fatalf("unexpected result: %#v", result)
	}
	results, err := store.ListPoCResults(ctx, session.ID, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ID != result.ID || results[0].CompletedAt == nil {
		t.Fatalf("expected persisted completed result, got %#v", results)
	}
}

func TestRunSkipsActiveValidationForOutOfScopeFindingURL(t *testing.T) {
	ctx := context.Background()
	store, session, finding := pocTestStoreWithURL(t, "Reflected XSS", "http://169.254.169.254/latest/meta-data")
	defer store.Close()
	client := &countingHTTPClient{}

	result, err := Run(ctx, store, session.ID, finding.ID, RunRequest{
		Confirm:                 true,
		ActiveValidationEnabled: true,
		Client:                  client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 0 {
		t.Fatalf("expected no outbound request for out-of-scope URL, got %d", client.calls)
	}
	if result.Status != models.PoCStatusFailed || !strings.Contains(result.Evidence, "outside session scope") {
		t.Fatalf("expected out-of-scope skip result, got %#v", result)
	}
}

func TestRunDoesNotFollowActiveValidationRedirectOutOfScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()
	ctx := context.Background()
	store, session, finding := pocTestStoreForTarget(t, "Reflected XSS", server.URL, server.URL+"/search?q=x")
	defer store.Close()

	result, err := Run(ctx, store, session.ID, finding.ID, RunRequest{
		Confirm:                 true,
		ActiveValidationEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ResponseCode != http.StatusFound || result.Status != models.PoCStatusInconclusive {
		t.Fatalf("expected redirect to be observed but not followed, got %#v", result)
	}
}

func pocTestStore(t *testing.T, title string) (*db.Store, models.Session, models.Finding) {
	return pocTestStoreWithURL(t, title, "https://example.test")
}

func pocTestStoreWithURL(t *testing.T, title, findingURL string) (*db.Store, models.Session, models.Finding) {
	return pocTestStoreForTarget(t, title, "https://example.test", findingURL)
}

func pocTestStoreForTarget(t *testing.T, title, targetInput, findingURL string) (*db.Store, models.Session, models.Finding) {
	t.Helper()
	ctx := context.Background()
	parsed, err := url.Parse(targetInput)
	if err != nil {
		t.Fatal(err)
	}
	port := 443
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &port); err != nil {
			t.Fatal(err)
		}
	}
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: targetInput, InScope: []string{targetInput}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: parsed.Hostname(), Port: port, Protocol: parsed.Scheme, IsAlive: true, CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityMedium, Title: title, Description: title, URL: findingURL, CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	return store, session, finding
}

type countingHTTPClient struct {
	calls int
}

func (c *countingHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, http.ErrServerClosed
}
