package llm

import (
	"os"
	"strconv"
	"strings"

	"github.com/kanini/nox/internal/models"
)

const (
	defaultProvider    = "openai-compatible"
	defaultMaxTokens   = 1024
	defaultTemperature = 0.2
)

type Config struct {
	Provider    string
	BaseURL     string
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float64
}

func ConfigFromSession(session models.Session) Config {
	config := Config{
		Provider:    firstNonEmpty(os.Getenv("NOX_LLM_PROVIDER"), defaultProvider),
		BaseURL:     firstNonEmpty(session.LLMBaseURL, os.Getenv("NOX_LLM_BASE_URL")),
		APIKey:      os.Getenv("NOX_LLM_API_KEY"),
		Model:       firstNonEmpty(session.LLMModel, os.Getenv("NOX_LLM_MODEL")),
		MaxTokens:   envInt("NOX_LLM_MAX_TOKENS", defaultMaxTokens),
		Temperature: envFloat("NOX_LLM_TEMPERATURE", defaultTemperature),
	}
	if config.Model == "" && config.BaseURL != "" {
		config.Model = "llama3:8b"
	}
	return config
}

func (c Config) Configured() bool {
	return strings.TrimSpace(c.BaseURL) != "" && strings.TrimSpace(c.Model) != ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envFloat(key string, fallback float64) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64)
	if err != nil {
		return fallback
	}
	return value
}
