package api

import (
	"regexp"

	"github.com/pridhvi/nyx/internal/models"
)

const maxCallbackEventDisplayBytes = 2048

var callbackSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s\r\n]+`),
	regexp.MustCompile(`(?i)(cookie\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password)=)[^&\s]+`),
}

func redactPowerCallbacks(callbacks []models.PowerCallback) []models.PowerCallback {
	out := append([]models.PowerCallback(nil), callbacks...)
	for i := range out {
		out[i].RawEvent = redactCallbackEvent(out[i].RawEvent)
	}
	return out
}

func redactCallbackEvent(value string) string {
	for _, pattern := range callbackSecretPatterns {
		value = pattern.ReplaceAllString(value, "${1}[redacted]")
	}
	if len(value) > maxCallbackEventDisplayBytes {
		value = value[:maxCallbackEventDisplayBytes] + "\n...[truncated]"
	}
	return value
}
