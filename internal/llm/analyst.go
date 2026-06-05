package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

var ErrNotConfigured = errors.New("llm is not configured")

const SystemPrompt = `You are the Nyx local security analyst. Use only the structured session context and tool results provided to you. Deterministic findings, CVE matches, and attack-vector rules are authoritative; do not invent vulnerabilities, targets, CVEs, exploitability, or scan results.

Your output is advisory. Default to defensive, non-invasive guidance: summarize evidence, explain risk, prioritize remediation, suggest safe scoped re-scans, recommend rotating or revoking exposed credentials, removing leaked secrets, reviewing logs, tightening configuration, or validating fixes in an authorized test environment.

Do not recommend using or validating exposed credentials, API keys, tokens, passwords, session cookies, or other secrets to see whether they are active. Do not recommend brute force, credential stuffing, exploitability validation, or active credential validation unless the operator explicitly asks for active validation and the request includes clear authorization and scope. If authorization is unclear, ask the operator to confirm scope instead of suggesting active use of secrets.

Follow-up scan requests must remain constrained to the current session scope, should be non-invasive by default, and are audit records only.`

type Analyst struct {
	store  Store
	client ChatCompleter
	config Config
}

func NewAnalyst(store Store, client ChatCompleter, config Config) Analyst {
	if client == nil {
		client = NewOpenAIClient(config)
	}
	return Analyst{store: store, client: client, config: config}
}

func (a Analyst) AnalyzeSession(ctx context.Context, sessionID, prompt string) (models.LLMAnalysis, error) {
	if !a.config.Configured() {
		return models.LLMAnalysis{}, ErrNotConfigured
	}
	sessionContext, err := BuildContext(ctx, a.store, sessionID)
	if err != nil {
		return models.LLMAnalysis{}, err
	}
	contextBody, err := json.Marshal(sessionContext)
	if err != nil {
		return models.LLMAnalysis{}, err
	}
	messages := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: SystemPrompt},
		{Role: openai.ChatMessageRoleUser, Content: "Session context JSON:\n" + string(contextBody)},
		{Role: openai.ChatMessageRoleUser, Content: prompt},
	}
	totalTokens := 0
	completion, err := a.client.Complete(ctx, ChatRequest{
		Model:       a.config.Model,
		Messages:    messages,
		Tools:       ToolDefinitions(),
		MaxTokens:   a.config.MaxTokens,
		Temperature: a.config.Temperature,
	})
	if err != nil {
		return models.LLMAnalysis{}, err
	}
	totalTokens += completion.TotalTokens
	messages = append(messages, completion.Message)

	toolCalls := executeToolCalls(ctx, a.store, sessionID, completion.Message.ToolCalls)
	if len(toolCalls) > 0 {
		for _, call := range toolCalls {
			content := call.Result
			if call.Error != "" {
				content = call.Error
			}
			messages = append(messages, openai.ChatCompletionMessage{
				Role:       openai.ChatMessageRoleTool,
				Content:    content,
				ToolCallID: call.ID,
			})
		}
		final, err := a.client.Complete(ctx, ChatRequest{
			Model:       a.config.Model,
			Messages:    messages,
			Tools:       ToolDefinitions(),
			MaxTokens:   a.config.MaxTokens,
			Temperature: a.config.Temperature,
		})
		if err != nil {
			return models.LLMAnalysis{}, err
		}
		totalTokens += final.TotalTokens
		messages = append(messages, final.Message)
	}
	analysis := models.LLMAnalysis{
		ID:            models.NewID(),
		SessionID:     sessionID,
		ModelID:       a.config.Model,
		PromptSummary: truncate(prompt, 160),
		Messages:      modelMessages(messages),
		TotalTokens:   totalTokens,
		CreatedAt:     time.Now().UTC(),
	}
	if err := analysis.Validate(); err != nil {
		return models.LLMAnalysis{}, err
	}
	if err := a.store.InsertLLMAnalysis(ctx, analysis); err != nil {
		return models.LLMAnalysis{}, err
	}
	_ = a.annotateAttackVectors(ctx, sessionID, sessionContext.AttackVectors, messages)
	return analysis, nil
}

func (a Analyst) annotateAttackVectors(ctx context.Context, sessionID string, vectors []models.AttackVector, messages []openai.ChatCompletionMessage) error {
	if len(vectors) == 0 {
		return nil
	}
	note := assistantReviewNote(messages)
	if note == "" {
		return nil
	}
	for _, vector := range vectors {
		if vector.SessionID != sessionID || vector.LLMReviewed {
			continue
		}
		if err := a.store.UpdateAttackVectorLLMReview(ctx, vector.ID, true, note); err != nil {
			return err
		}
	}
	return nil
}

func assistantReviewNote(messages []openai.ChatCompletionMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == openai.ChatMessageRoleAssistant && strings.TrimSpace(assistantVisibleContent(messages[i])) != "" {
			return truncate(strings.TrimSpace(assistantVisibleContent(messages[i])), 1200)
		}
	}
	return ""
}

func executeToolCalls(ctx context.Context, store Store, sessionID string, calls []openai.ToolCall) []models.LLMToolCall {
	runner := NewToolRunner(store)
	var results []models.LLMToolCall
	for _, call := range calls {
		result := models.LLMToolCall{ID: call.ID, Name: call.Function.Name, Arguments: call.Function.Arguments}
		output, err := runner.Execute(ctx, sessionID, call)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Result = output
		}
		results = append(results, result)
	}
	return results
}
