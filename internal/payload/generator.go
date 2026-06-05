package payload

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	openai "github.com/sashabaranov/go-openai"
)

type GenerateOptions struct {
	Force     bool
	LLMConfig llmintel.Config
	LLMClient llmintel.ChatCompleter
}

func Generate(ctx context.Context, store *db.Store, sessionID, findingID string, options GenerateOptions) ([]models.Payload, error) {
	finding, err := store.GetFinding(ctx, sessionID, findingID)
	if err != nil {
		return nil, err
	}
	if !options.Force {
		existing, err := store.ListPayloadsByFinding(ctx, sessionID, findingID)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return existing, nil
		}
	}
	if options.Force {
		if err := store.DeletePayloadsByFinding(ctx, sessionID, findingID); err != nil {
			return nil, err
		}
	}
	generated := llmPayloads(ctx, finding, options)
	if len(generated) == 0 {
		generated = deterministicPayloads(finding)
		markPayloadSource(generated, "Deterministic fallback payload.")
	} else {
		markPayloadSource(generated, "LLM-generated advisory payload.")
	}
	if len(generated) == 0 {
		return nil, fmt.Errorf("finding %q is not a supported payload generation target", finding.ID)
	}
	now := time.Now().UTC()
	for i := range generated {
		generated[i].ID = models.NewID()
		generated[i].SessionID = sessionID
		generated[i].FindingID = findingID
		generated[i].Rank = i + 1
		generated[i].CreatedAt = now
		if err := store.InsertPayload(ctx, generated[i]); err != nil {
			return nil, err
		}
	}
	return store.ListPayloadsByFinding(ctx, sessionID, findingID)
}

func llmPayloads(ctx context.Context, finding models.Finding, options GenerateOptions) []models.Payload {
	if !options.LLMConfig.Configured() {
		return nil
	}
	client := options.LLMClient
	if client == nil {
		client = llmintel.NewOpenAIClient(options.LLMConfig)
	}
	prompt := `Generate safe, non-destructive payload suggestions for this vulnerability as JSON only.
Return an array of objects with keys payload_type, payload, context, target_waf, target_db, bypass_technique, confidence.
Do not include destructive payloads, exfiltration, credential theft, shell downloaders, or real data access.
Finding JSON:
` + findingContext(finding)
	completion, err := client.Complete(ctx, llmintel.ChatRequest{
		Model: options.LLMConfig.Model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You generate bounded, non-destructive penetration-test payload suggestions for authorized testing. Output valid JSON only."},
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
		MaxTokens:   options.LLMConfig.MaxTokens,
		Temperature: options.LLMConfig.Temperature,
	})
	if err != nil {
		return nil
	}
	var payloads []models.Payload
	if err := json.Unmarshal([]byte(extractJSONArray(completion.Message.Content)), &payloads); err != nil {
		return nil
	}
	out := payloads[:0]
	for _, payload := range payloads {
		payload.PayloadType = strings.TrimSpace(payload.PayloadType)
		payload.Payload = strings.TrimSpace(payload.Payload)
		if payload.PayloadType == "" || payload.Payload == "" || unsafePayload(payload.Payload) {
			continue
		}
		if payload.Confidence <= 0 || payload.Confidence > 1 {
			payload.Confidence = 0.5
		}
		if payload.Context == "" {
			payload.Context = "Not sent automatically."
		}
		out = append(out, payload)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func markPayloadSource(payloads []models.Payload, prefix string) {
	for i := range payloads {
		context := strings.TrimSpace(payloads[i].Context)
		switch {
		case context == "":
			payloads[i].Context = prefix
		case strings.HasPrefix(context, prefix):
			payloads[i].Context = context
		default:
			payloads[i].Context = prefix + " " + context
		}
	}
}

func findingContext(finding models.Finding) string {
	body, err := json.Marshal(map[string]any{
		"title":       finding.Title,
		"description": finding.Description,
		"type":        finding.Type,
		"tool_id":     finding.ToolID,
		"url":         finding.URL,
		"parameter":   finding.Parameter,
		"method":      finding.Method,
		"severity":    finding.Severity,
		"evidence":    finding.EvidenceNormalized,
		"tags":        finding.Tags,
	})
	if err != nil {
		return "{}"
	}
	return string(body)
}

func extractJSONArray(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "```") {
		value = strings.TrimPrefix(value, "```json")
		value = strings.TrimPrefix(value, "```")
		value = strings.TrimSuffix(value, "```")
		value = strings.TrimSpace(value)
	}
	start := strings.Index(value, "[")
	end := strings.LastIndex(value, "]")
	if start >= 0 && end > start {
		return value[start : end+1]
	}
	return value
}

func unsafePayload(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"rm -rf", "curl ", "wget ", "/etc/shadow", "aws_secret", "metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func deterministicPayloads(finding models.Finding) []models.Payload {
	text := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, string(finding.Type), finding.ToolID, finding.Parameter, finding.URL}, " "))
	switch {
	case strings.Contains(text, "xss") || strings.Contains(text, "script") || strings.Contains(text, "reflected"):
		return []models.Payload{
			{PayloadType: "xss", Payload: `"><script>confirm("nyx")</script>`, Context: "Reflected marker payload; generation is advisory and not sent automatically.", BypassTechnique: "quote-breakout", Confidence: 0.62},
			{PayloadType: "xss", Payload: `<img src=x onerror=confirm("nyx")>`, Context: "Event-handler marker payload for manual validation.", BypassTechnique: "event-handler", Confidence: 0.56},
		}
	case strings.Contains(text, "sql") || strings.Contains(text, "sqli"):
		return []models.Payload{
			{PayloadType: "sqli", Payload: `' OR '1'='1' --`, Context: "Boolean SQL injection probe; use only with explicit authorization.", BypassTechnique: "boolean-tautology", Confidence: 0.58}, // #nosec G101 -- this is a generated SQLi marker payload, not a credential.
			{PayloadType: "sqli", Payload: `' AND 1=2 UNION SELECT NULL --`, Context: "Union-shape probe for manual testing.", BypassTechnique: "union-probe", Confidence: 0.42},
		}
	case strings.Contains(text, "ssrf"):
		return []models.Payload{{PayloadType: "ssrf", Payload: `http://127.0.0.1:9/nyx-canary`, Context: "Local-only canary URL placeholder; external callback support is separate.", BypassTechnique: "loopback-canary", Confidence: 0.35}}
	case strings.Contains(text, "ssti") || strings.Contains(text, "template"):
		return []models.Payload{{PayloadType: "ssti", Payload: `{{7*7}}`, Context: "Harmless arithmetic marker for manual SSTI validation.", BypassTechnique: "arithmetic-marker", Confidence: 0.54}}
	case strings.Contains(text, "xxe"):
		return []models.Payload{{PayloadType: "xxe", Payload: `<!DOCTYPE x [<!ENTITY nyx "nyx">]>`, Context: "Non-exfiltrating entity marker.", BypassTechnique: "entity-marker", Confidence: 0.31}}
	case strings.Contains(text, "redirect"):
		return []models.Payload{{PayloadType: "open_redirect", Payload: `https://example.com/nyx-redirect-marker`, Context: "Benign external redirect marker.", BypassTechnique: "absolute-url", Confidence: 0.5}}
	case strings.Contains(text, "command") || strings.Contains(text, "rce"):
		return []models.Payload{{PayloadType: "cmd_injection", Payload: `; echo nyx-marker`, Context: "Harmless echo marker; not automatically verifiable.", BypassTechnique: "shell-separator", Confidence: 0.28}} // #nosec G101 -- this is a generated command-injection marker payload, not a credential.
	default:
		return nil
	}
}
