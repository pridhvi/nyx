package payload

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

func TestGenerateReusesExistingPayloadsUnlessForced(t *testing.T) {
	ctx := context.Background()
	store, session, finding := payloadTestStore(t, "Reflected XSS")
	defer store.Close()

	first, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(second) != len(first) || second[0].ID != first[0].ID {
		t.Fatalf("expected reuse, first=%#v second=%#v", first, second)
	}
	forced, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(forced) != len(first) || forced[0].ID == first[0].ID {
		t.Fatalf("expected regenerated payload IDs, first=%#v forced=%#v", first, forced)
	}
}

func TestGenerateRejectsUnsupportedFinding(t *testing.T) {
	ctx := context.Background()
	store, session, finding := payloadTestStore(t, "Informational banner")
	defer store.Close()
	_, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err == nil || !strings.Contains(err.Error(), "not a supported") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func TestGenerateLabelsLLMAndDeterministicPayloadSources(t *testing.T) {
	ctx := context.Background()
	store, session, finding := payloadTestStore(t, "Reflected XSS")
	defer store.Close()

	generated, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{
		Force: true,
		LLMConfig: llmintel.Config{
			Provider: "openai-compatible",
			BaseURL:  "http://localhost:11434/v1",
			Model:    "test-model",
		},
		LLMClient: fakePayloadCompleter{content: `[{"payload_type":"xss","payload":"<img src=x onerror=confirm(\"nyx\")>","context":"event-handler marker","confidence":0.7}]`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 1 || !strings.HasPrefix(generated[0].Context, "LLM-generated advisory payload.") {
		t.Fatalf("expected LLM source label, got %#v", generated)
	}

	fallback, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fallback) == 0 || !strings.HasPrefix(fallback[0].Context, "Deterministic fallback payload.") {
		t.Fatalf("expected deterministic source label, got %#v", fallback)
	}
}

func TestValidatePayloadRequiresConfirmAndUpdatesEvidence(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "reflected %s", r.URL.Query().Get("q"))
	}))
	defer server.Close()

	store, session, finding := payloadTestStoreForTarget(t, "Reflected XSS", server.URL+"/search?q=x")
	defer store.Close()
	generated, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(ctx, store, session, generated[0].ID, ValidationOptions{Enabled: true}); err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Fatalf("expected confirmation error, got %v", err)
	}
	result, err := Validate(ctx, store, session, generated[0].ID, ValidationOptions{Confirm: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Validated || !strings.Contains(result.Evidence, "XSS marker") {
		t.Fatalf("expected validated marker evidence, got %#v", result)
	}
}

type fakePayloadCompleter struct {
	content string
}

func (f fakePayloadCompleter) Complete(ctx context.Context, request llmintel.ChatRequest) (llmintel.ChatCompletion, error) {
	return llmintel.ChatCompletion{
		Message:     openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: f.content},
		TotalTokens: 7,
	}, nil
}

func TestValidatePayloadRejectsOutOfScopeRedirect(t *testing.T) {
	ctx := context.Background()
	outOfScopeHit := 0
	outOfScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outOfScopeHit++
		_, _ = w.Write([]byte("confirm nyx"))
	}))
	defer outOfScope.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScope.URL, http.StatusFound)
	}))
	defer server.Close()

	inScopeURL := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	store, session, finding := payloadTestStoreForTarget(t, "Reflected XSS", inScopeURL+"/search?q=x")
	defer store.Close()
	generated, err := Generate(ctx, store, session.ID, finding.ID, GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Validate(ctx, store, session, generated[0].ID, ValidationOptions{Confirm: true, Enabled: true})
	if err == nil || !strings.Contains(err.Error(), "rejected by scope") {
		t.Fatalf("expected scoped redirect rejection, got %v", err)
	}
	if outOfScopeHit != 0 {
		t.Fatalf("expected out-of-scope redirect to be blocked, got %d hits", outOfScopeHit)
	}
}

func payloadTestStore(t *testing.T, title string) (*db.Store, models.Session, models.Finding) {
	return payloadTestStoreForTarget(t, title, "https://example.test/?q=x")
}

func payloadTestStoreForTarget(t *testing.T, title, findingURL string) (*db.Store, models.Session, models.Finding) {
	t.Helper()
	ctx := context.Background()
	req, _ := http.NewRequest(http.MethodGet, findingURL, nil)
	port := 443
	protocol := "https"
	if req.URL.Scheme == "http" {
		port = 80
		protocol = "http"
	}
	if req.URL.Port() != "" {
		fmt.Sscanf(req.URL.Port(), "%d", &port)
	}
	scope := req.URL.Scheme + "://" + req.URL.Host
	session := models.Session{ID: models.NewID(), Status: models.SessionStatusCompleted, Mode: models.ScanModeActive, TargetInput: scope, InScope: []string{scope}, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: models.NewID(), SessionID: session.ID, Host: req.URL.Hostname(), Port: port, Protocol: protocol, IsAlive: true, CreatedAt: time.Now().UTC()}
	dir := t.TempDir()
	if _, err := db.CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	store, err := db.OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{ID: models.NewID(), SessionID: session.ID, TargetID: target.ID, ToolID: "test", Type: models.FindingTypeVulnerability, Severity: models.SeverityHigh, Title: title, Description: title, URL: findingURL, Tags: []string{"test"}, CreatedAt: time.Now().UTC()}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	return store, session, finding
}
