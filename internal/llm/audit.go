package llm

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

type AuditStore interface {
	UpdateFindingAuditFields(ctx context.Context, finding models.Finding) error
	InsertLLMAnalysis(ctx context.Context, analysis models.LLMAnalysis) error
}

type AuditAnalyst struct {
	store  AuditStore
	client ChatCompleter
	config Config
}

func NewAuditAnalyst(store AuditStore, client ChatCompleter, config Config) AuditAnalyst {
	if client == nil {
		client = NewOpenAIClient(config)
	}
	return AuditAnalyst{store: store, client: client, config: config}
}

func (a AuditAnalyst) ReviewFindings(ctx context.Context, sessionID string, findings []models.Finding, repoPath string) error {
	if !a.config.Configured() {
		return ErrNotConfigured
	}
	for i := 0; i < len(findings); i += 10 {
		end := i + 10
		if end > len(findings) {
			end = len(findings)
		}
		if err := a.triageBatch(ctx, sessionID, findings[i:end], repoPath); err != nil {
			return err
		}
	}
	return nil
}

func (a AuditAnalyst) triageBatch(ctx context.Context, sessionID string, findings []models.Finding, repoPath string) error {
	body, _ := json.Marshal(findings)
	messages := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: "You are a senior application security engineer triaging SAST findings. Respond only with a JSON array of objects with id, verdict, confidence, and reason."},
		{Role: openai.ChatMessageRoleUser, Content: "Repository: " + repoPath + "\nFindings JSON:\n" + string(body)},
	}
	completion, err := a.client.Complete(ctx, ChatRequest{Model: a.config.Model, Messages: messages, MaxTokens: a.config.MaxTokens, Temperature: a.config.Temperature})
	if err != nil {
		return err
	}
	messages = append(messages, completion.Message)
	verdicts := map[string]struct {
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Reason     string  `json:"reason"`
	}{}
	var decoded []struct {
		ID         string  `json:"id"`
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Reason     string  `json:"reason"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(completion.Message.Content)), &decoded); err == nil {
		for _, item := range decoded {
			verdicts[item.ID] = struct {
				Verdict    string  `json:"verdict"`
				Confidence float64 `json:"confidence"`
				Reason     string  `json:"reason"`
			}{item.Verdict, item.Confidence, item.Reason}
		}
	}
	for _, finding := range findings {
		verdict := verdicts[finding.ID]
		switch verdict.Verdict {
		case "false_positive":
			finding.Status = "dismissed"
		default:
			finding.Status = "confirmed"
		}
		if verdict.Confidence > 0 {
			finding.Confidence = verdict.Confidence
		}
		if verdict.Reason != "" {
			finding.Notes = verdict.Reason
		}
		if err := a.store.UpdateFindingAuditFields(ctx, finding); err != nil {
			return err
		}
	}
	analysis := models.LLMAnalysis{ID: models.NewID(), SessionID: sessionID, ModelID: a.config.Model, PromptSummary: "Audit triage", Messages: modelMessages(messages), TotalTokens: completion.TotalTokens, CreatedAt: time.Now().UTC()}
	return a.store.InsertLLMAnalysis(ctx, analysis)
}
