package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ChatCompleter interface {
	Complete(ctx context.Context, request ChatRequest) (ChatCompletion, error)
}

type ChatRequest struct {
	Model       string
	Messages    []ChatMessage
	Tools       []ToolDefinition
	MaxTokens   int
	Temperature float64
}

type ChatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []ChatToolCall `json:"tool_calls,omitempty"`
}

type ChatToolCall struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments,omitempty"`
	Result    string `json:"-"`
	Error     string `json:"-"`
}

type ChatCompletion struct {
	Message     ChatMessage
	TotalTokens int
}

type OpenAIClient struct {
	config Config
	client *http.Client
}

func NewOpenAIClient(config Config) *OpenAIClient {
	return &OpenAIClient{
		config: config,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *OpenAIClient) Complete(ctx context.Context, request ChatRequest) (ChatCompletion, error) {
	if !c.config.Configured() {
		return ChatCompletion{}, ErrNotConfigured
	}
	payload := chatCompletionRequest{
		Model:       request.Model,
		Messages:    request.Messages,
		Tools:       request.Tools,
		MaxTokens:   request.MaxTokens,
		Temperature: request.Temperature,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ChatCompletion{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatCompletionsURL(c.config.BaseURL), bytes.NewReader(body))
	if err != nil {
		return ChatCompletion{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ChatCompletion{}, err
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		return ChatCompletion{}, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ChatCompletion{}, fmt.Errorf("llm request failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var decoded chatCompletionResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return ChatCompletion{}, err
	}
	if len(decoded.Choices) == 0 {
		return ChatCompletion{}, fmt.Errorf("llm response contained no choices")
	}
	message := ChatMessage{
		Role:    decoded.Choices[0].Message.Role,
		Content: decoded.Choices[0].Message.Content,
	}
	for _, call := range decoded.Choices[0].Message.ToolCalls {
		message.ToolCalls = append(message.ToolCalls, ChatToolCall{
			ID:        call.ID,
			Name:      call.Function.Name,
			Arguments: call.Function.Arguments,
		})
	}
	return ChatCompletion{Message: message, TotalTokens: decoded.Usage.TotalTokens}, nil
}

func chatCompletionsURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(base, "/chat/completions") {
		return base
	}
	if strings.HasSuffix(base, "/v1") {
		return base + "/chat/completions"
	}
	return base + "/v1/chat/completions"
}

type chatCompletionRequest struct {
	Model       string           `json:"model"`
	Messages    []ChatMessage    `json:"messages"`
	Tools       []ToolDefinition `json:"tools,omitempty"`
	MaxTokens   int              `json:"max_tokens,omitempty"`
	Temperature float64          `json:"temperature"`
}

func (c ChatToolCall) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID       string `json:"id,omitempty"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}{
		ID:   c.ID,
		Type: "function",
		Function: struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{
			Name:      c.Name,
			Arguments: c.Arguments,
		},
	})
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}
