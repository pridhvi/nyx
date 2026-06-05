package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

func TestConfigFromSessionRequiresBaseURL(t *testing.T) {
	t.Setenv("NYX_LLM_BASE_URL", "")
	t.Setenv("NYX_LLM_MODEL", "")
	session := models.Session{}

	if got := ConfigFromSession(session); got.Configured() {
		t.Fatalf("expected unconfigured LLM without a base URL, got %#v", got)
	}

	session.LLMBaseURL = "http://localhost:11434/v1"
	got := ConfigFromSession(session)
	if !got.Configured() || got.Model == "" {
		t.Fatalf("expected configured local LLM with default model, got %#v", got)
	}
}

func TestValidateBaseURLHonorsAllowedHosts(t *testing.T) {
	if err := ValidateBaseURL("http://127.0.0.1:1234/v1", []string{"localhost"}); err == nil {
		t.Fatal("expected disallowed host to be rejected")
	}
	if err := ValidateBaseURL("http://metadata.google.internal./v1", nil); err == nil {
		t.Fatal("expected metadata endpoint to be rejected")
	}
	if err := ValidateBaseURL("http://127.0.0.1:1234/v1", nil); err == nil {
		t.Fatal("expected loopback endpoint without allowlist to be rejected")
	}
	if err := ValidateBaseURL("http://10.0.0.100:1234/v1", nil); err == nil {
		t.Fatal("expected private endpoint without allowlist to be rejected")
	}
	if err := ValidateBaseURL("http://127.0.0.1:1234/v1", []string{"127.0.0.1"}); err != nil {
		t.Fatalf("expected explicitly allowed loopback LLM host, got %v", err)
	}
	if err := ValidateBaseURL("http://localhost:1234/v1", []string{"localhost"}); err != nil {
		t.Fatalf("expected allowed LLM host, got %v", err)
	}
}

func TestHTTPClientRejectsRedirectToDisallowedHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1:11434/v1/models", http.StatusFound)
	}))
	defer server.Close()

	client := NewHTTPClient([]string{"127.0.0.1"}, time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "configured allowlist") {
		t.Fatalf("expected redirect allowlist rejection, got resp=%v err=%v", resp, err)
	}
}

func TestHTTPClientRejectsPrivateConnectWithoutAllowlist(t *testing.T) {
	client := NewHTTPClient(nil, time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.1:11434/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "explicit allowlist") {
		t.Fatalf("expected connect-time private endpoint rejection, got resp=%v err=%v", resp, err)
	}
}

func TestOpenAIClientValidatesBaseURLAtInvocation(t *testing.T) {
	client := NewOpenAIClient(Config{
		Provider: "openai-compatible",
		BaseURL:  "http://127.0.0.1:1234/v1",
		Model:    "stored-session-model",
	})
	_, err := client.Complete(context.Background(), ChatRequest{
		Model:    "stored-session-model",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hello"}},
	})
	if err == nil || !strings.Contains(err.Error(), "explicit allowlist") {
		t.Fatalf("expected invocation-time base URL validation, got %v", err)
	}
}

func TestOpenAIClientStreamValidatesBaseURLAtInvocation(t *testing.T) {
	client := NewOpenAIClient(Config{
		Provider: "openai-compatible",
		BaseURL:  "http://127.0.0.1:1234/v1",
		Model:    "stored-session-model",
	})
	_, err := client.CompleteStream(context.Background(), ChatRequest{
		Model:    "stored-session-model",
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "hello"}},
	})
	if err == nil || !strings.Contains(err.Error(), "explicit allowlist") {
		t.Fatalf("expected stream invocation-time base URL validation, got %v", err)
	}
}

func TestBuildContextTruncatesEvidenceAndIncludesStructuredData(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)

	sessionContext, err := BuildContext(ctx, store, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sessionContext.Session.ID != session.ID {
		t.Fatalf("expected session %s, got %#v", session.ID, sessionContext.Session)
	}
	if len(sessionContext.Targets) != 1 || len(sessionContext.Targets[0].Technologies) != 1 {
		t.Fatalf("expected target technology context, got %#v", sessionContext.Targets)
	}
	if len(sessionContext.Findings) != 1 || !strings.Contains(sessionContext.Findings[0].EvidenceRaw, "[truncated]") {
		t.Fatalf("expected truncated finding evidence, got %#v", sessionContext.Findings)
	}
	if len(sessionContext.CVEMatches) != 1 || len(sessionContext.AttackVectors) != 1 {
		t.Fatalf("expected CVE and attack-vector context, got cves=%#v vectors=%#v", sessionContext.CVEMatches, sessionContext.AttackVectors)
	}
}

func TestAnalystPersistsConversationAndToolAuditTrail(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)
	client := &fakeCompleter{responses: []ChatCompletion{
		{
			Message: openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleAssistant,
				Content: "I need the findings first.",
				ToolCalls: []openai.ToolCall{{
					ID:   "call-1",
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      "get_session_findings",
						Arguments: `{"severity":"high"}`,
					},
				}},
			},
			TotalTokens: 8,
		},
		{
			Message:     openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: "The high-risk finding is supported by persisted evidence."},
			TotalTokens: 12,
		},
	}}

	analysis, err := NewAnalyst(store, client, Config{
		Provider:    "openai-compatible",
		BaseURL:     "http://localhost:11434/v1",
		Model:       "llama3:8b",
		MaxTokens:   256,
		Temperature: 0.1,
	}).AnalyzeSession(ctx, session.ID, "Summarize the scan.")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.TotalTokens != 20 {
		t.Fatalf("expected token accounting, got %d", analysis.TotalTokens)
	}
	if len(client.requests) != 2 {
		t.Fatalf("expected tool loop to make two requests, got %d", len(client.requests))
	}
	analyses, err := store.ListLLMAnalyses(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected persisted analysis, got %#v", analyses)
	}
	foundToolResult := false
	for _, message := range analyses[0].Messages {
		for _, call := range message.ToolCalls {
			if call.Name == "tool_result" && strings.Contains(call.Result, "Test high finding") {
				foundToolResult = true
			}
		}
	}
	if !foundToolResult {
		t.Fatalf("expected visible tool-call result in audit trail, got %#v", analyses[0].Messages)
	}
	vectors, err := store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 || !vectors[0].LLMReviewed || !strings.Contains(vectors[0].LLMNotes, "persisted evidence") {
		t.Fatalf("expected LLM-reviewed vector annotation, got %#v", vectors)
	}
}

func TestAnalystHandlesMultipleToolRoundsBeforeFinalAnswer(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)
	client := &fakeCompleter{responses: []ChatCompletion{
		{
			Message: openai.ChatCompletionMessage{
				Role: openai.ChatMessageRoleAssistant,
				ToolCalls: []openai.ToolCall{{
					ID:   "call-1",
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      "get_session_findings",
						Arguments: `{"severity":"high"}`,
					},
				}},
			},
			TotalTokens: 4,
		},
		{
			Message: openai.ChatCompletionMessage{
				Role: openai.ChatMessageRoleAssistant,
				ToolCalls: []openai.ToolCall{{
					ID:   "call-2",
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      "search_cves_for_technology",
						Arguments: `{"technology":"OpenSSL"}`,
					},
				}},
			},
			TotalTokens: 5,
		},
		{
			Message:     openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: "Final answer after two tool rounds."},
			TotalTokens: 6,
		},
	}}

	analysis, err := NewAnalyst(store, client, Config{
		Provider:    "openai-compatible",
		BaseURL:     "http://localhost:11434/v1",
		Model:       "llama3:8b",
		MaxTokens:   256,
		Temperature: 0.1,
	}).AnalyzeSession(ctx, session.ID, "Use tools as needed.")
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 3 {
		t.Fatalf("expected three model requests, got %d", len(client.requests))
	}
	if analysis.TotalTokens != 15 {
		t.Fatalf("expected token accounting across rounds, got %d", analysis.TotalTokens)
	}
	toolResultCount := 0
	for _, message := range analysis.Messages {
		for _, call := range message.ToolCalls {
			if call.Name == "tool_result" {
				toolResultCount++
			}
		}
	}
	if toolResultCount != 2 {
		t.Fatalf("expected two persisted tool results, got %d in %#v", toolResultCount, analysis.Messages)
	}
	vectors, err := store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 || !vectors[0].LLMReviewed || vectors[0].LLMNotes != "Final answer after two tool rounds." {
		t.Fatalf("expected final answer to annotate vector, got %#v", vectors)
	}
}

func TestAnalystForcesFinalAnswerAfterToolRoundLimit(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)
	var responses []ChatCompletion
	for i := 0; i <= maxToolRounds; i++ {
		responses = append(responses, ChatCompletion{
			Message: openai.ChatCompletionMessage{
				Role: openai.ChatMessageRoleAssistant,
				ToolCalls: []openai.ToolCall{{
					ID:   "call-limit",
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      "get_session_findings",
						Arguments: `{}`,
					},
				}},
			},
			TotalTokens: 1,
		})
	}
	responses = append(responses, ChatCompletion{
		Message:     openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: "Final answer without tools."},
		TotalTokens: 2,
	})
	client := &fakeCompleter{responses: responses}

	analysis, err := NewAnalyst(store, client, Config{
		Provider:    "openai-compatible",
		BaseURL:     "http://localhost:11434/v1",
		Model:       "llama3:8b",
		MaxTokens:   256,
		Temperature: 0.1,
	}).AnalyzeSession(ctx, session.ID, "Do not stop calling tools.")
	if err != nil {
		t.Fatal(err)
	}
	lastRequest := client.requests[len(client.requests)-1]
	if len(lastRequest.Tools) != 0 {
		t.Fatalf("expected final fallback request to disable tools, got %#v", lastRequest.Tools)
	}
	if !strings.Contains(lastRequest.Messages[len(lastRequest.Messages)-1].Content, "Do not call tools") {
		t.Fatalf("expected final fallback instruction, got %#v", lastRequest.Messages[len(lastRequest.Messages)-1])
	}
	if got := analysis.Messages[len(analysis.Messages)-1].Content; got != "Final answer without tools." {
		t.Fatalf("expected persisted final answer, got %q", got)
	}
}

func TestSystemPromptDefaultsToDefensiveCredentialGuidance(t *testing.T) {
	required := []string{
		"Default to defensive, non-invasive guidance",
		"suggest realistic attack chains, impact hypotheses, and safe validation strategies",
		"authorized security assessment work",
		"Prefer proof strategies that avoid data access",
		"rotating or revoking exposed credentials",
		"Do not recommend using or validating exposed credentials",
		"active credential validation unless the operator explicitly asks",
		"clear authorization and scope",
	}
	for _, phrase := range required {
		if !strings.Contains(SystemPrompt, phrase) {
			t.Fatalf("system prompt missing %q:\n%s", phrase, SystemPrompt)
		}
	}
}

func TestAnalystSendsHardenedSystemPrompt(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)
	client := &fakeCompleter{}

	_, err := NewAnalyst(store, client, Config{
		Provider:    "openai-compatible",
		BaseURL:     "http://localhost:11434/v1",
		Model:       "llama3:8b",
		MaxTokens:   256,
		Temperature: 0.1,
	}).AnalyzeSession(ctx, session.ID, "What should I do about leaked credentials?")
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 1 || len(client.requests[0].Messages) == 0 {
		t.Fatalf("expected one LLM request with messages, got %#v", client.requests)
	}
	system := client.requests[0].Messages[0]
	if system.Role != openai.ChatMessageRoleSystem {
		t.Fatalf("expected first message to be system prompt, got %#v", system)
	}
	if !strings.Contains(system.Content, "Do not recommend using or validating exposed credentials") ||
		!strings.Contains(system.Content, "active credential validation unless the operator explicitly asks") {
		t.Fatalf("expected hardened credential guidance in system prompt, got %q", system.Content)
	}
}

func TestRequestScanToolDescriptionDiscouragesActiveCredentialValidation(t *testing.T) {
	for _, tool := range ToolDefinitions() {
		if tool.Function == nil || tool.Function.Name != "request_scan" {
			continue
		}
		description := tool.Function.Description
		required := []string{
			"safe, non-invasive",
			"Do not request active credential validation",
			"secret use",
			"explicitly authorized",
		}
		for _, phrase := range required {
			if !strings.Contains(description, phrase) {
				t.Fatalf("request_scan description missing %q: %s", phrase, description)
			}
		}
		return
	}
	t.Fatal("request_scan tool definition not found")
}

func TestOpenAIClientPreservesReasoningContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-test",
			"object": "chat.completion",
			"model": "lmstudio-reasoner",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "",
					"reasoning_content": "Reasoning-derived answer from LM Studio."
				},
				"finish_reason": "length"
			}],
			"usage": {"prompt_tokens": 4, "completion_tokens": 8, "total_tokens": 12}
		}`))
	}))
	defer server.Close()

	client := NewOpenAIClient(Config{Provider: "openai-compatible", BaseURL: server.URL + "/v1", Model: "lmstudio-reasoner", AllowedHosts: []string{"127.0.0.1"}})
	completion, err := client.Complete(context.Background(), ChatRequest{
		Model:     "lmstudio-reasoner",
		Messages:  []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "summarize"}},
		MaxTokens: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completion.Message.Content != "" || completion.Message.ReasoningContent != "Reasoning-derived answer from LM Studio." {
		t.Fatalf("expected reasoning_content preservation, got %#v", completion.Message)
	}
	if completion.TotalTokens != 12 {
		t.Fatalf("expected token accounting, got %d", completion.TotalTokens)
	}
}

func TestOpenAIClientStreamPreservesReasoningContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"Reasoning\"},\"finish_reason\":null}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"2\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\" stream answer\"},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":9}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer server.Close()

	client := NewOpenAIClient(Config{Provider: "openai-compatible", BaseURL: server.URL + "/v1", Model: "lmstudio-reasoner", AllowedHosts: []string{"127.0.0.1"}})
	completion, err := client.CompleteStream(context.Background(), ChatRequest{
		Model:     "lmstudio-reasoner",
		Messages:  []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "summarize"}},
		MaxTokens: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completion.Message.Content != "" || completion.Message.ReasoningContent != "Reasoning stream answer" {
		t.Fatalf("expected streamed reasoning_content preservation, got %#v", completion.Message)
	}
}

func TestModelMessageSplitsReasoningPrefixedOutput(t *testing.T) {
	message := modelMessage(openai.ChatCompletionMessage{
		Role: openai.ChatMessageRoleAssistant,
		Content: strings.Join([]string{
			"Thinking Process:",
			"Review the scan context.",
			"",
			"Final Answer:",
			"- **Risk:** confirmed SQL injection",
		}, "\n"),
	})
	if message.Content != "- **Risk:** confirmed SQL injection" {
		t.Fatalf("expected final answer content, got %#v", message)
	}
	if message.ReasoningContent != "Review the scan context." {
		t.Fatalf("expected reasoning content, got %#v", message)
	}
	if !strings.Contains(message.RawContent, "Thinking Process:") {
		t.Fatalf("expected raw content to be preserved, got %#v", message)
	}
}

func TestModelMessageUsesPlaceholderForReasoningOnlyOutput(t *testing.T) {
	message := modelMessage(openai.ChatCompletionMessage{
		Role:             openai.ChatMessageRoleAssistant,
		ReasoningContent: "Inspect findings before answering.",
	})
	if message.Content != reasoningOnlyPlaceholder {
		t.Fatalf("expected reasoning-only placeholder, got %#v", message)
	}
	if message.ReasoningContent != "Inspect findings before answering." {
		t.Fatalf("expected reasoning content, got %#v", message)
	}
}

func TestModelMessageRemovesFinalAnswerLabelWithNativeReasoning(t *testing.T) {
	message := modelMessage(openai.ChatCompletionMessage{
		Role:             openai.ChatMessageRoleAssistant,
		ReasoningContent: "Inspect findings before answering.",
		Content:          "- **Risk:** confirmed SQL injection\n\nFinal Answer: Confirmed SQL injection is the strongest risk.",
	})
	if strings.Contains(message.Content, "Final Answer:") {
		t.Fatalf("expected final answer label to be removed, got %#v", message)
	}
	if !strings.Contains(message.Content, "confirmed SQL injection") || !strings.Contains(message.Content, "Confirmed SQL injection") {
		t.Fatalf("expected visible content to be preserved, got %#v", message)
	}
	if message.RawContent == "" {
		t.Fatalf("expected raw content to be preserved when visible content is cleaned, got %#v", message)
	}
}

func TestToolRunnerConstrainsScanRequestsToSessionScope(t *testing.T) {
	ctx := context.Background()
	session, store := testLLMStore(t, ctx)
	runner := NewToolRunner(store)

	result, err := runner.Execute(ctx, session.ID, openai.ToolCall{
		Type: openai.ToolTypeFunction,
		Function: openai.FunctionCall{
			Name:      "request_scan",
			Arguments: `{"target":"https://evil.example","tool":"http-probe","reason":"check it"}`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"accepted":false`) || !strings.Contains(result, `"in_scope":false`) {
		t.Fatalf("expected out-of-scope scan request denial, got %s", result)
	}
	result, err = runner.Execute(ctx, session.ID, openai.ToolCall{
		Type: openai.ToolTypeFunction,
		Function: openai.FunctionCall{
			Name:      "request_scan",
			Arguments: `{"target":"https://example.com.evil.test","tool":"http-probe","reason":"check it"}`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"in_scope":false`) {
		t.Fatalf("expected lookalike domain denial, got %s", result)
	}
	result, err = runner.Execute(ctx, session.ID, openai.ToolCall{
		Type: openai.ToolTypeFunction,
		Function: openai.FunctionCall{
			Name:      "request_scan",
			Arguments: `{"target":"https://api.example.com","tool":"http-probe","reason":"check it"}`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"in_scope":false`) {
		t.Fatalf("expected exact host scope to reject subdomain, got %s", result)
	}
	wildcard := session
	wildcard.TargetInput = "*.example.com"
	wildcard.InScope = []string{"*.example.com"}
	if !targetAllowed("https://api.example.com", wildcard) {
		t.Fatal("expected wildcard scope to allow subdomain")
	}
}

type fakeCompleter struct {
	responses []ChatCompletion
	requests  []ChatRequest
}

func (f *fakeCompleter) Complete(ctx context.Context, request ChatRequest) (ChatCompletion, error) {
	f.requests = append(f.requests, request)
	if len(f.responses) == 0 {
		return ChatCompletion{Message: openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: "done"}}, nil
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response, nil
}

func testLLMStore(t *testing.T, ctx context.Context) (models.Session, *db.Store) {
	t.Helper()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "LLM Test",
		Status:      models.SessionStatusCompleted,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"https://example.com"},
		LLMModel:    "llama3:8b",
		LLMBaseURL:  "http://localhost:11434/v1",
		CreatedAt:   now,
	}
	if err := store.InsertSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	target := models.Target{
		ID:           models.NewID(),
		SessionID:    session.ID,
		Host:         "example.com",
		Port:         443,
		Protocol:     "https",
		IsAlive:      true,
		DiscoveredBy: "test",
		CreatedAt:    now,
	}
	technology := models.Technology{
		ID:         models.NewID(),
		TargetID:   target.ID,
		Name:       "OpenSSL",
		Version:    "1.0.1",
		Category:   "tls",
		Confidence: 0.9,
		SourceTool: "test",
	}
	target.Technologies = []models.Technology{technology}
	if err := store.InsertTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	finding := models.Finding{
		ID:                 models.NewID(),
		SessionID:          session.ID,
		TargetID:           target.ID,
		ToolID:             "test-tool",
		Type:               models.FindingTypeVulnerability,
		Severity:           models.SeverityHigh,
		Confidence:         0.95,
		CVSSScore:          8.1,
		Title:              "Test high finding",
		Description:        "A high finding used for LLM context.",
		Remediation:        "Patch it.",
		URL:                "https://example.com",
		EvidenceRaw:        strings.Repeat("e", evidenceLimit+20),
		EvidenceNormalized: strings.Repeat("n", evidenceLimit+20),
		Tags:               []string{"test"},
		CreatedAt:          now,
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertCVEMatch(ctx, models.CVEMatch{
		ID:              models.NewID(),
		FindingID:       finding.ID,
		TechnologyID:    technology.ID,
		CVEID:           "CVE-2024-0001",
		CVSSv3Score:     8.1,
		Description:     "Test CVE",
		Source:          "test",
		ConfidenceScore: 0.8,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertAttackVector(ctx, models.AttackVector{
		ID:               models.NewID(),
		SessionID:        session.ID,
		Title:            "Exploit known vulnerable component",
		Description:      "A deterministic vector.",
		Narrative:        "Use persisted evidence only.",
		OWASPCategory:    "A06",
		Severity:         models.SeverityHigh,
		Confidence:       0.8,
		PrereqFindingIDs: []string{finding.ID},
		Steps: []models.AttackStep{{
			Order:       1,
			Description: "Review finding.",
			FindingID:   finding.ID,
		}},
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return session, store
}
