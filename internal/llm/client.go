package llm

import (
	"context"
	"fmt"
	"io"
	"strings"

	openai "github.com/sashabaranov/go-openai"
)

type ChatCompleter interface {
	Complete(ctx context.Context, request ChatRequest) (ChatCompletion, error)
}

type ChatRequest struct {
	Model       string
	Messages    []openai.ChatCompletionMessage
	Tools       []openai.Tool
	MaxTokens   int
	Temperature float64
}

type ChatCompletion struct {
	Message     openai.ChatCompletionMessage
	TotalTokens int
}

type OpenAIClient struct {
	config Config
	client *openai.Client
}

func NewClient(baseURL, apiKey string) *openai.Client {
	cfg := openai.DefaultConfig(apiKey)
	cfg.BaseURL = baseURL
	return openai.NewClientWithConfig(cfg)
}

func NewOpenAIClient(config Config) *OpenAIClient {
	return &OpenAIClient{
		config: config,
		client: NewClient(config.BaseURL, config.APIKey),
	}
}

func (c *OpenAIClient) Complete(ctx context.Context, request ChatRequest) (ChatCompletion, error) {
	if !c.config.Configured() {
		return ChatCompletion{}, ErrNotConfigured
	}
	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:       request.Model,
		Messages:    request.Messages,
		Tools:       request.Tools,
		MaxTokens:   request.MaxTokens,
		Temperature: float32(request.Temperature),
	})
	if err != nil {
		return ChatCompletion{}, err
	}
	if len(resp.Choices) == 0 {
		return ChatCompletion{}, fmt.Errorf("llm response contained no choices")
	}
	message := normalizeAssistantMessage(resp.Choices[0].Message)
	return ChatCompletion{Message: message, TotalTokens: resp.Usage.TotalTokens}, nil
}

func (c *OpenAIClient) CompleteStream(ctx context.Context, request ChatRequest) (ChatCompletion, error) {
	if !c.config.Configured() {
		return ChatCompletion{}, ErrNotConfigured
	}
	stream, err := c.client.CreateChatCompletionStream(ctx, openai.ChatCompletionRequest{
		Model:       request.Model,
		Messages:    request.Messages,
		Tools:       request.Tools,
		MaxTokens:   request.MaxTokens,
		Temperature: float32(request.Temperature),
		Stream:      true,
		StreamOptions: &openai.StreamOptions{
			IncludeUsage: true,
		},
	})
	if err != nil {
		return ChatCompletion{}, err
	}
	defer stream.Close()

	message := openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant}
	totalTokens := 0
	toolCalls := map[int]openai.ToolCall{}
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ChatCompletion{}, err
		}
		if chunk.Usage != nil {
			totalTokens = chunk.Usage.TotalTokens
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		delta := chunk.Choices[0].Delta
		if delta.Role != "" {
			message.Role = delta.Role
		}
		message.Content += delta.Content
		message.ReasoningContent += delta.ReasoningContent
		for _, call := range delta.ToolCalls {
			if call.Index == nil {
				message.ToolCalls = append(message.ToolCalls, call)
				continue
			}
			existing := toolCalls[*call.Index]
			if call.ID != "" {
				existing.ID = call.ID
			}
			if call.Type != "" {
				existing.Type = call.Type
			}
			existing.Function.Name += call.Function.Name
			existing.Function.Arguments += call.Function.Arguments
			toolCalls[*call.Index] = existing
		}
	}
	if len(toolCalls) > 0 {
		message.ToolCalls = make([]openai.ToolCall, 0, len(toolCalls))
		for i := 0; i < len(toolCalls); i++ {
			if call, ok := toolCalls[i]; ok {
				message.ToolCalls = append(message.ToolCalls, call)
			}
		}
	}
	return ChatCompletion{Message: normalizeAssistantMessage(message), TotalTokens: totalTokens}, nil
}

func normalizeAssistantMessage(message openai.ChatCompletionMessage) openai.ChatCompletionMessage {
	if strings.TrimSpace(message.Content) == "" && strings.TrimSpace(message.ReasoningContent) != "" {
		message.Content = strings.TrimSpace(message.ReasoningContent)
	}
	return message
}
