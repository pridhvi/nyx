package llm

import (
	"regexp"
	"strings"

	"github.com/pridhvi/nyx/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

const reasoningOnlyPlaceholder = "The model returned reasoning only and no final answer."

var (
	thinkTagPattern       = regexp.MustCompile(`(?is)^<think>\s*(.*?)\s*</think>\s*(.*)$`)
	reasoningLabelPattern = regexp.MustCompile(`(?is)^(thinking process|reasoning|thought process)\s*:\s*`)
	finalLabelPattern     = regexp.MustCompile(`(?is)\n\s*(final answer|final output|answer|response|final)\s*:\s*`)
)

type splitReasoningResult struct {
	Reasoning string
	Answer    string
	Matched   bool
}

func modelMessages(messages []openai.ChatCompletionMessage) []models.LLMMessage {
	out := make([]models.LLMMessage, 0, len(messages))
	for _, message := range messages {
		modelMessage := modelMessage(message)
		for _, call := range message.ToolCalls {
			modelMessage.ToolCalls = append(modelMessage.ToolCalls, models.LLMToolCall{
				ID:        call.ID,
				Name:      call.Function.Name,
				Arguments: call.Function.Arguments,
			})
		}
		if message.Role == openai.ChatMessageRoleTool {
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

func modelMessage(message openai.ChatCompletionMessage) models.LLMMessage {
	modelMessage := models.LLMMessage{Role: message.Role, Content: message.Content}
	if message.Role != openai.ChatMessageRoleAssistant {
		return modelMessage
	}

	rawContent := strings.TrimSpace(message.Content)
	reasoningContent := strings.TrimSpace(message.ReasoningContent)
	if reasoningContent != "" {
		modelMessage.ReasoningContent = reasoningContent
		if rawContent == "" {
			modelMessage.Content = reasoningOnlyPlaceholder
			return modelMessage
		}
	}

	split := splitReasoningContent(rawContent)
	if !split.Matched {
		return modelMessage
	}
	modelMessage.RawContent = rawContent
	modelMessage.ReasoningContent = split.Reasoning
	if split.Answer == "" {
		modelMessage.Content = reasoningOnlyPlaceholder
	} else {
		modelMessage.Content = split.Answer
	}
	return modelMessage
}

func assistantVisibleContent(message openai.ChatCompletionMessage) string {
	return modelMessage(message).Content
}

func splitReasoningContent(content string) splitReasoningResult {
	normalized := strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	if normalized == "" {
		return splitReasoningResult{}
	}
	if match := thinkTagPattern.FindStringSubmatch(normalized); match != nil {
		return splitReasoningResult{Reasoning: strings.TrimSpace(match[1]), Answer: strings.TrimSpace(match[2]), Matched: true}
	}
	label := reasoningLabelPattern.FindStringIndex(normalized)
	if label == nil || label[0] != 0 {
		return splitReasoningResult{}
	}
	body := strings.TrimSpace(normalized[label[1]:])
	if match := finalLabelPattern.FindStringIndex(body); match != nil {
		return splitReasoningResult{
			Reasoning: strings.TrimSpace(body[:match[0]]),
			Answer:    strings.TrimSpace(body[match[1]:]),
			Matched:   true,
		}
	}
	return splitReasoningResult{Reasoning: body, Matched: true}
}
