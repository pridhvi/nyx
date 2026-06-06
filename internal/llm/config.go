package llm

import (
	"os"
	"strconv"
	"strings"

	appconfig "github.com/pridhvi/nyx/internal/config"
	"github.com/pridhvi/nyx/internal/models"
)

const (
	defaultProvider    = "openai-compatible"
	defaultMaxTokens   = 1024
	defaultTemperature = 0.2
)

type Config struct {
	Provider     string
	BaseURL      string
	APIKey       string
	Model        string
	MaxTokens    int
	Temperature  float64
	AllowedHosts []string
}

func ConfigFromSession(session models.Session) Config {
	config := Config{
		Provider:     firstNonEmpty(os.Getenv("NYX_LLM_PROVIDER"), defaultProvider),
		BaseURL:      firstNonEmpty(session.LLMBaseURL, os.Getenv("NYX_LLM_BASE_URL")),
		APIKey:       os.Getenv("NYX_LLM_API_KEY"),
		Model:        firstNonEmpty(session.LLMModel, os.Getenv("NYX_LLM_MODEL")),
		MaxTokens:    envInt("NYX_LLM_MAX_TOKENS", defaultMaxTokens),
		Temperature:  envFloat("NYX_LLM_TEMPERATURE", defaultTemperature),
		AllowedHosts: AllowedHostsFromEnv(),
	}
	if config.Model == "" && config.BaseURL != "" {
		config.Model = "llama3:8b"
	}
	return config
}

func ConfigFromSessionWithApp(session models.Session, cfg appconfig.Config) Config {
	config := ConfigFromApp(cfg)
	if strings.TrimSpace(session.LLMBaseURL) != "" {
		config.BaseURL = strings.TrimSpace(session.LLMBaseURL)
	}
	if strings.TrimSpace(session.LLMModel) != "" {
		config.Model = strings.TrimSpace(session.LLMModel)
	}
	if config.Model == "" && config.BaseURL != "" {
		config.Model = "llama3:8b"
	}
	return config
}

func ConfigFromApp(cfg appconfig.Config) Config {
	config := Config{
		Provider:     firstNonEmpty(os.Getenv("NYX_LLM_PROVIDER"), cfg.LLM.Provider, defaultProvider),
		BaseURL:      firstNonEmpty(os.Getenv("NYX_LLM_BASE_URL"), cfg.LLM.BaseURL),
		APIKey:       firstNonEmpty(os.Getenv("NYX_LLM_API_KEY"), cfg.LLM.APIKey),
		Model:        firstNonEmpty(os.Getenv("NYX_LLM_MODEL"), cfg.LLM.Model),
		MaxTokens:    firstPositive(envInt("NYX_LLM_MAX_TOKENS", 0), cfg.LLM.MaxTokens, defaultMaxTokens),
		Temperature:  firstFloat(os.Getenv("NYX_LLM_TEMPERATURE"), cfg.LLM.Temperature, defaultTemperature),
		AllowedHosts: AllowedHostsFromEnv(),
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

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstFloat(env string, values ...float64) float64 {
	if strings.TrimSpace(env) != "" {
		if value, err := strconv.ParseFloat(strings.TrimSpace(env), 64); err == nil {
			return value
		}
	}
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
