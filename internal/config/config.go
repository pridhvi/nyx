package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	LLM      LLMConfig         `json:"llm"`
	Database DatabaseConfig    `json:"database"`
	Server   ServerConfig      `json:"server"`
	Scan     ScanConfig        `json:"scan"`
	CVE      CVEConfig         `json:"cve"`
	Tools    map[string]string `json:"tools"`
	Plugins  []string          `json:"plugins"`
}

type LLMConfig struct {
	Provider    string  `json:"provider"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	Model       string  `json:"model"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	Enabled     bool    `json:"enabled"`
}

type DatabaseConfig struct {
	SessionDir string `json:"session_dir"`
}

type ServerConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	APIKey string `json:"api_key"`
}

type ScanConfig struct {
	Mode        string   `json:"mode"`
	Phases      []string `json:"phases"`
	Tools       []string `json:"tools"`
	Concurrency int      `json:"concurrency"`
	RateLimit   string   `json:"rate_limit"`
}

type CVEConfig struct {
	OfflinePath  string `json:"offline_path"`
	EnableRemote bool   `json:"enable_remote"`
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".nox", "config.yaml")
	}
	return filepath.Join(home, ".nox", "config.yaml")
}

func Default() Config {
	return Config{
		LLM: LLMConfig{
			Provider:    "openai-compatible",
			BaseURL:     "",
			APIKey:      "",
			Model:       "llama3:8b",
			MaxTokens:   1024,
			Temperature: 0.2,
			Enabled:     false,
		},
		Database: DatabaseConfig{SessionDir: filepath.Join(".nox", "sessions")},
		Server:   ServerConfig{Host: "127.0.0.1", Port: 8080},
		Scan:     ScanConfig{Mode: "active", Concurrency: 4},
		CVE:      CVEConfig{EnableRemote: false},
		Tools:    map[string]string{},
		Plugins:  []string{},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ApplyEnv(cfg), nil
		}
		return Config{}, err
	}
	applyYAML(&cfg, string(data))
	return ApplyEnv(cfg), nil
}

func WriteDefault(path string) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(Default().YAML()), 0o644)
}

func ApplyEnv(cfg Config) Config {
	cfg.LLM.Provider = first(os.Getenv("NOX_LLM_PROVIDER"), cfg.LLM.Provider)
	cfg.LLM.BaseURL = first(os.Getenv("NOX_LLM_BASE_URL"), cfg.LLM.BaseURL)
	cfg.LLM.APIKey = first(os.Getenv("NOX_LLM_API_KEY"), cfg.LLM.APIKey)
	cfg.LLM.Model = first(os.Getenv("NOX_LLM_MODEL"), cfg.LLM.Model)
	cfg.Database.SessionDir = first(os.Getenv("NOX_SESSION_DIR"), cfg.Database.SessionDir)
	cfg.Server.APIKey = first(os.Getenv("NOX_API_KEY"), cfg.Server.APIKey)
	cfg.CVE.OfflinePath = first(os.Getenv("NOX_CVE_OFFLINE_PATH"), cfg.CVE.OfflinePath)
	if value := os.Getenv("NOX_CVE_ENABLE_REMOTE"); strings.TrimSpace(value) != "" {
		cfg.CVE.EnableRemote = parseBool(value)
	}
	if value := os.Getenv("NOX_LLM_MAX_TOKENS"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.LLM.MaxTokens = parsed
		}
	}
	if value := os.Getenv("NOX_LLM_TEMPERATURE"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.LLM.Temperature = parsed
		}
	}
	return cfg
}

func (c Config) YAML() string {
	return fmt.Sprintf(`# Nox configuration
llm:
  enabled: %t
  provider: %s
  base_url: %s
  api_key: %s
  model: %s
  max_tokens: %d
  temperature: %.2f
database:
  session_dir: %s
server:
  host: %s
  port: %d
  api_key: %s
scan:
  mode: %s
  phases: %s
  tools: %s
  concurrency: %d
  rate_limit: %s
cve:
  offline_path: %s
  enable_remote: %t
tools: {}
plugins: []
`, c.LLM.Enabled, c.LLM.Provider, c.LLM.BaseURL, c.LLM.APIKey, c.LLM.Model, c.LLM.MaxTokens, c.LLM.Temperature,
		c.Database.SessionDir, c.Server.Host, c.Server.Port, c.Server.APIKey, c.Scan.Mode, strings.Join(c.Scan.Phases, ","), strings.Join(c.Scan.Tools, ","), c.Scan.Concurrency, c.Scan.RateLimit,
		c.CVE.OfflinePath, c.CVE.EnableRemote)
}

func applyYAML(cfg *Config, data string) {
	section := ""
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch section + "." + key {
		case "llm.enabled":
			cfg.LLM.Enabled = parseBool(value)
		case "llm.provider":
			cfg.LLM.Provider = value
		case "llm.base_url":
			cfg.LLM.BaseURL = value
		case "llm.api_key":
			cfg.LLM.APIKey = value
		case "llm.model":
			cfg.LLM.Model = value
		case "llm.max_tokens":
			if parsed, err := strconv.Atoi(value); err == nil {
				cfg.LLM.MaxTokens = parsed
			}
		case "llm.temperature":
			if parsed, err := strconv.ParseFloat(value, 64); err == nil {
				cfg.LLM.Temperature = parsed
			}
		case "database.session_dir":
			cfg.Database.SessionDir = value
		case "server.host":
			cfg.Server.Host = value
		case "server.port":
			if parsed, err := strconv.Atoi(value); err == nil {
				cfg.Server.Port = parsed
			}
		case "server.api_key":
			cfg.Server.APIKey = value
		case "scan.mode":
			cfg.Scan.Mode = value
		case "scan.phases":
			cfg.Scan.Phases = splitCSV(value)
		case "scan.tools":
			cfg.Scan.Tools = splitCSV(value)
		case "scan.concurrency":
			if parsed, err := strconv.Atoi(value); err == nil {
				cfg.Scan.Concurrency = parsed
			}
		case "scan.rate_limit":
			cfg.Scan.RateLimit = value
		case "cve.offline_path":
			cfg.CVE.OfflinePath = value
		case "cve.enable_remote":
			cfg.CVE.EnableRemote = parseBool(value)
		}
	}
}

func first(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func splitCSV(value string) []string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
