package models

import "time"

type LLMAnalysis struct {
	ID            string       `json:"id"`
	SessionID     string       `json:"session_id"`
	ModelID       string       `json:"model_id"`
	PromptSummary string       `json:"prompt_summary"`
	Messages      []LLMMessage `json:"messages"`
	TotalTokens   int          `json:"total_tokens"`
	CreatedAt     time.Time    `json:"created_at"`
}

type LLMMessage struct {
	Role             string        `json:"role"`
	Content          string        `json:"content"`
	ReasoningContent string        `json:"reasoning_content,omitempty"`
	RawContent       string        `json:"raw_content,omitempty"`
	ToolCalls        []LLMToolCall `json:"tool_calls,omitempty"`
}

type LLMToolCall struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments,omitempty"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
}
