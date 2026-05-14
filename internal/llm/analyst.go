package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

var ErrNotConfigured = errors.New("llm is not configured")

const SystemPrompt = `You are the Nox local security analyst. Use only the structured session context and tool results provided to you. Deterministic findings, CVE matches, and attack-vector rules are authoritative; do not invent vulnerabilities, targets, CVEs, exploitability, or scan results. You may summarize evidence, explain risk, suggest safe follow-up checks, and call available tools. Follow-up scan requests must remain constrained to the current session scope and are audit records only.`

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
	messages := []ChatMessage{
		{Role: "system", Content: SystemPrompt},
		{Role: "user", Content: "Session context JSON:\n" + string(contextBody)},
		{Role: "user", Content: prompt},
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
		messages[len(messages)-1].ToolCalls = mergeToolResults(messages[len(messages)-1].ToolCalls, toolCalls)
		for _, call := range toolCalls {
			content := call.Result
			if call.Error != "" {
				content = call.Error
			}
			messages = append(messages, ChatMessage{
				Role:       "tool",
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
	return analysis, nil
}

func executeToolCalls(ctx context.Context, store Store, sessionID string, calls []ChatToolCall) []models.LLMToolCall {
	runner := NewToolRunner(store)
	var results []models.LLMToolCall
	for _, call := range calls {
		result := models.LLMToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments}
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

func mergeToolResults(calls []ChatToolCall, results []models.LLMToolCall) []ChatToolCall {
	if len(calls) == 0 || len(results) == 0 {
		return calls
	}
	byID := map[string]models.LLMToolCall{}
	byName := map[string]models.LLMToolCall{}
	for _, result := range results {
		if result.ID != "" {
			byID[result.ID] = result
		}
		byName[result.Name] = result
	}
	for i := range calls {
		result, ok := byID[calls[i].ID]
		if !ok {
			result, ok = byName[calls[i].Name]
		}
		if ok {
			calls[i].Result = result.Result
			calls[i].Error = result.Error
		}
	}
	return calls
}

func modelMessages(messages []ChatMessage) []models.LLMMessage {
	out := make([]models.LLMMessage, 0, len(messages))
	for _, message := range messages {
		modelMessage := models.LLMMessage{Role: message.Role, Content: message.Content}
		for _, call := range message.ToolCalls {
			modelMessage.ToolCalls = append(modelMessage.ToolCalls, models.LLMToolCall{
				ID:        call.ID,
				Name:      call.Name,
				Arguments: call.Arguments,
				Result:    call.Result,
				Error:     call.Error,
			})
		}
		if message.Role == "tool" {
			modelMessage.ToolCalls = append(modelMessage.ToolCalls, models.LLMToolCall{
				ID:     message.ToolCallID,
				Name:   "tool_result",
				Result: message.Content,
			})
		}
		out = append(out, modelMessage)
	}
	return out
}

func gracefulLLMError(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, ErrNotConfigured) || strings.Contains(err.Error(), "connection refused")
}
