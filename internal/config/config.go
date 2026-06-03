package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	LLM      LLMConfig         `json:"llm"`
	Database DatabaseConfig    `json:"database"`
	Server   ServerConfig      `json:"server"`
	Logging  LoggingConfig     `json:"logging"`
	Scan     ScanConfig        `json:"scan"`
	CVE      CVEConfig         `json:"cve"`
	Power    PowerConfig       `json:"power"`
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
	Host          string `json:"host"`
	Port          int    `json:"port"`
	APIKey        string `json:"api_key"`
	SecureCookies bool   `json:"secure_cookies"`
}

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type ScanConfig struct {
	Mode        string   `json:"mode"`
	Phases      []string `json:"phases"`
	Tools       []string `json:"tools"`
	Concurrency int      `json:"concurrency"`
	RateLimit   string   `json:"rate_limit"`
}

type CVEConfig struct {
	OfflinePath   string   `json:"offline_path"`
	EnableRemote  bool     `json:"enable_remote"`
	CacheTTL      string   `json:"cache_ttl"`
	ExploitDBPath string   `json:"exploitdb_path"`
	Sources       []string `json:"sources"`
}

type PowerConfig struct {
	Providers        PowerProviderConfig   `json:"providers"`
	Burp             PowerBurpConfig       `json:"burp"`
	Callbacks        PowerCallbackConfig   `json:"callbacks"`
	Credentials      PowerCredentialConfig `json:"credentials"`
	ActiveValidation PowerValidationConfig `json:"active_validation"`
}

type PowerProviderConfig struct {
	GitHubToken          string `json:"github_token"`
	ShodanAPIKey         string `json:"shodan_api_key"`
	SecurityTrailsAPIKey string `json:"securitytrails_api_key"`
}

type PowerBurpConfig struct {
	BaseURL      string   `json:"base_url"`
	APIKey       string   `json:"api_key"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type PowerCallbackConfig struct {
	Provider      string `json:"provider"`
	InteractshURL string `json:"interactsh_url"`
}

type PowerCredentialConfig struct {
	MaxAttemptsPerUser int  `json:"max_attempts_per_user"`
	DelaySeconds       int  `json:"delay_seconds"`
	StorePlaintext     bool `json:"store_plaintext"`
}

type PowerValidationConfig struct {
	Enabled bool `json:"enabled"`
}

func (c PowerConfig) Redacted() PowerConfig {
	if c.Providers.GitHubToken != "" {
		c.Providers.GitHubToken = "********"
	}
	if c.Providers.ShodanAPIKey != "" {
		c.Providers.ShodanAPIKey = "********"
	}
	if c.Providers.SecurityTrailsAPIKey != "" {
		c.Providers.SecurityTrailsAPIKey = "********"
	}
	if c.Burp.APIKey != "" {
		c.Burp.APIKey = "********"
	}
	return c
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".nyx", "config.yaml")
	}
	return filepath.Join(home, ".nyx", "config.yaml")
}

func Default() Config {
	sessionDir := filepath.Join(".nyx", "sessions")
	if home, err := os.UserHomeDir(); err == nil {
		sessionDir = filepath.Join(home, ".nyx", "sessions")
	}
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
		Database: DatabaseConfig{SessionDir: sessionDir},
		Server:   ServerConfig{Host: "127.0.0.1", Port: 6767},
		Logging:  LoggingConfig{Level: "info", Format: "text"},
		Scan:     ScanConfig{Mode: "active", Concurrency: 4},
		CVE:      CVEConfig{EnableRemote: false, CacheTTL: "24h", Sources: []string{"embedded"}},
		Power: PowerConfig{
			Callbacks:        PowerCallbackConfig{Provider: "builtin"},
			Credentials:      PowerCredentialConfig{MaxAttemptsPerUser: 3, DelaySeconds: 3, StorePlaintext: false},
			ActiveValidation: PowerValidationConfig{Enabled: false},
		},
		Tools:   map[string]string{},
		Plugins: []string{},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	v := viper.New()
	setDefaults(v, cfg)
	v.SetConfigFile(path)
	if filepath.Ext(path) == "" {
		v.SetConfigType("yaml")
	}
	v.SetEnvPrefix("NYX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	bindEnv(v)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && !os.IsNotExist(err) {
			return Config{}, err
		}
	}
	cfg.LLM.Provider = v.GetString("llm.provider")
	cfg.LLM.BaseURL = v.GetString("llm.base_url")
	cfg.LLM.APIKey = v.GetString("llm.api_key")
	cfg.LLM.Model = v.GetString("llm.model")
	cfg.LLM.MaxTokens = v.GetInt("llm.max_tokens")
	cfg.LLM.Temperature = v.GetFloat64("llm.temperature")
	cfg.LLM.Enabled = v.GetBool("llm.enabled")
	cfg.Database.SessionDir = resolvePath(v.GetString("database.session_dir"), filepath.Dir(path))
	cfg.Server.Host = v.GetString("server.host")
	cfg.Server.Port = v.GetInt("server.port")
	cfg.Server.APIKey = v.GetString("server.api_key")
	cfg.Server.SecureCookies = v.GetBool("server.secure_cookies")
	cfg.Logging.Level = v.GetString("logging.level")
	cfg.Logging.Format = v.GetString("logging.format")
	cfg.Scan.Mode = v.GetString("scan.mode")
	cfg.Scan.Phases = getStringSlice(v, "scan.phases")
	cfg.Scan.Tools = getStringSlice(v, "scan.tools")
	cfg.Scan.Concurrency = v.GetInt("scan.concurrency")
	cfg.Scan.RateLimit = v.GetString("scan.rate_limit")
	cfg.CVE.OfflinePath = v.GetString("cve.offline_path")
	cfg.CVE.EnableRemote = v.GetBool("cve.enable_remote")
	cfg.CVE.CacheTTL = v.GetString("cve.cache_ttl")
	cfg.CVE.ExploitDBPath = v.GetString("cve.exploitdb_path")
	cfg.CVE.Sources = getStringSlice(v, "cve.sources")
	cfg.Power.Providers.GitHubToken = v.GetString("power.providers.github_token")
	cfg.Power.Providers.ShodanAPIKey = v.GetString("power.providers.shodan_api_key")
	cfg.Power.Providers.SecurityTrailsAPIKey = v.GetString("power.providers.securitytrails_api_key")
	cfg.Power.Burp.BaseURL = v.GetString("power.burp.base_url")
	cfg.Power.Burp.APIKey = v.GetString("power.burp.api_key")
	cfg.Power.Burp.AllowedHosts = getStringSlice(v, "power.burp.allowed_hosts")
	cfg.Power.Callbacks.Provider = v.GetString("power.callbacks.provider")
	cfg.Power.Callbacks.InteractshURL = v.GetString("power.callbacks.interactsh_url")
	cfg.Power.Credentials.MaxAttemptsPerUser = v.GetInt("power.credentials.max_attempts_per_user")
	cfg.Power.Credentials.DelaySeconds = v.GetInt("power.credentials.delay_seconds")
	cfg.Power.Credentials.StorePlaintext = v.GetBool("power.credentials.store_plaintext")
	cfg.Power.ActiveValidation.Enabled = v.GetBool("power.active_validation.enabled")
	cfg.Tools = v.GetStringMapString("tools")
	cfg.Plugins = getStringSlice(v, "plugins")
	return ApplyEnv(cfg), nil
}

func WriteDefault(path string) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(Default().YAML()), 0o600)
}

func ApplyEnv(cfg Config) Config {
	cfg.LLM.Provider = first(os.Getenv("NYX_LLM_PROVIDER"), cfg.LLM.Provider)
	cfg.LLM.BaseURL = first(os.Getenv("NYX_LLM_BASE_URL"), cfg.LLM.BaseURL)
	cfg.LLM.APIKey = first(os.Getenv("NYX_LLM_API_KEY"), cfg.LLM.APIKey)
	cfg.LLM.Model = first(os.Getenv("NYX_LLM_MODEL"), cfg.LLM.Model)
	cfg.Database.SessionDir = absolutePath(first(os.Getenv("NYX_SESSION_DIR"), cfg.Database.SessionDir))
	cfg.Server.APIKey = first(os.Getenv("NYX_API_KEY"), cfg.Server.APIKey)
	if value := os.Getenv("NYX_SECURE_COOKIES"); strings.TrimSpace(value) != "" {
		cfg.Server.SecureCookies = parseBool(value)
	}
	cfg.Logging.Level = first(os.Getenv("NYX_LOG_LEVEL"), cfg.Logging.Level)
	cfg.Logging.Format = first(os.Getenv("NYX_LOG_FORMAT"), cfg.Logging.Format)
	cfg.CVE.OfflinePath = first(os.Getenv("NYX_CVE_OFFLINE_PATH"), cfg.CVE.OfflinePath)
	cfg.CVE.ExploitDBPath = first(os.Getenv("NYX_CVE_EXPLOITDB_PATH"), cfg.CVE.ExploitDBPath)
	cfg.CVE.CacheTTL = first(os.Getenv("NYX_CVE_CACHE_TTL"), cfg.CVE.CacheTTL)
	cfg.Power.Providers.GitHubToken = first(os.Getenv("NYX_POWER_PROVIDERS_GITHUB_TOKEN"), cfg.Power.Providers.GitHubToken)
	cfg.Power.Providers.ShodanAPIKey = first(os.Getenv("NYX_POWER_PROVIDERS_SHODAN_API_KEY"), cfg.Power.Providers.ShodanAPIKey)
	cfg.Power.Providers.SecurityTrailsAPIKey = first(os.Getenv("NYX_POWER_PROVIDERS_SECURITYTRAILS_API_KEY"), cfg.Power.Providers.SecurityTrailsAPIKey)
	cfg.Power.Burp.BaseURL = first(os.Getenv("NYX_POWER_BURP_BASE_URL"), cfg.Power.Burp.BaseURL)
	cfg.Power.Burp.APIKey = first(os.Getenv("NYX_POWER_BURP_API_KEY"), cfg.Power.Burp.APIKey)
	cfg.Power.Burp.AllowedHosts = append(cfg.Power.Burp.AllowedHosts, splitCSV(os.Getenv("NYX_BURP_ALLOWED_HOSTS"))...)
	cfg.Power.Callbacks.Provider = first(os.Getenv("NYX_POWER_CALLBACKS_PROVIDER"), cfg.Power.Callbacks.Provider)
	cfg.Power.Callbacks.InteractshURL = first(os.Getenv("NYX_POWER_CALLBACKS_INTERACTSH_URL"), cfg.Power.Callbacks.InteractshURL)
	if value := os.Getenv("NYX_CVE_ENABLE_REMOTE"); strings.TrimSpace(value) != "" {
		cfg.CVE.EnableRemote = parseBool(value)
	}
	if value := os.Getenv("NYX_POWER_CREDENTIALS_MAX_ATTEMPTS_PER_USER"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.Power.Credentials.MaxAttemptsPerUser = parsed
		}
	}
	if value := os.Getenv("NYX_POWER_CREDENTIALS_DELAY_SECONDS"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.Power.Credentials.DelaySeconds = parsed
		}
	}
	if value := os.Getenv("NYX_POWER_CREDENTIALS_STORE_PLAINTEXT"); strings.TrimSpace(value) != "" {
		cfg.Power.Credentials.StorePlaintext = parseBool(value)
	}
	if value := os.Getenv("NYX_POWER_ACTIVE_VALIDATION_ENABLED"); strings.TrimSpace(value) != "" {
		cfg.Power.ActiveValidation.Enabled = parseBool(value)
	}
	if value := os.Getenv("NYX_LLM_MAX_TOKENS"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.LLM.MaxTokens = parsed
		}
	}
	if value := os.Getenv("NYX_LLM_TEMPERATURE"); strings.TrimSpace(value) != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.LLM.Temperature = parsed
		}
	}
	return cfg
}

func resolvePath(value, baseDir string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	value = expandHome(value)
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

func absolutePath(value string) string {
	value = strings.TrimSpace(value)
	value = expandHome(value)
	if value == "" || filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return filepath.Clean(value)
	}
	return abs
}

func expandHome(value string) string {
	if value == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
	}
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	return value
}

func (c Config) YAML() string {
	return fmt.Sprintf(`# Nyx configuration
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
  secure_cookies: %t
logging:
  level: %s
  format: %s
scan:
  mode: %s
  phases: %s
  tools: %s
  concurrency: %d
  rate_limit: %s
cve:
  offline_path: %s
  enable_remote: %t
  cache_ttl: %s
  exploitdb_path: %s
  sources: %s
power:
  providers:
    github_token: %s
    shodan_api_key: %s
    securitytrails_api_key: %s
  burp:
    base_url: %s
    api_key: %s
    allowed_hosts: %s
  callbacks:
    provider: %s
    interactsh_url: %s
  credentials:
    max_attempts_per_user: %d
    delay_seconds: %d
    store_plaintext: %t
  active_validation:
    enabled: %t
tools: {}
plugins: []
`, c.LLM.Enabled, c.LLM.Provider, c.LLM.BaseURL, c.LLM.APIKey, c.LLM.Model, c.LLM.MaxTokens, c.LLM.Temperature,
		c.Database.SessionDir, c.Server.Host, c.Server.Port, c.Server.APIKey, c.Server.SecureCookies, c.Logging.Level, c.Logging.Format, c.Scan.Mode, strings.Join(c.Scan.Phases, ","), strings.Join(c.Scan.Tools, ","), c.Scan.Concurrency, c.Scan.RateLimit,
		c.CVE.OfflinePath, c.CVE.EnableRemote, c.CVE.CacheTTL, c.CVE.ExploitDBPath, strings.Join(c.CVE.Sources, ","),
		c.Power.Providers.GitHubToken, c.Power.Providers.ShodanAPIKey, c.Power.Providers.SecurityTrailsAPIKey,
		c.Power.Burp.BaseURL, c.Power.Burp.APIKey, strings.Join(c.Power.Burp.AllowedHosts, ","), c.Power.Callbacks.Provider, c.Power.Callbacks.InteractshURL,
		c.Power.Credentials.MaxAttemptsPerUser, c.Power.Credentials.DelaySeconds, c.Power.Credentials.StorePlaintext,
		c.Power.ActiveValidation.Enabled)
}

func first(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func setDefaults(v *viper.Viper, cfg Config) {
	v.SetDefault("llm.enabled", cfg.LLM.Enabled)
	v.SetDefault("llm.provider", cfg.LLM.Provider)
	v.SetDefault("llm.base_url", cfg.LLM.BaseURL)
	v.SetDefault("llm.api_key", cfg.LLM.APIKey)
	v.SetDefault("llm.model", cfg.LLM.Model)
	v.SetDefault("llm.max_tokens", cfg.LLM.MaxTokens)
	v.SetDefault("llm.temperature", cfg.LLM.Temperature)
	v.SetDefault("database.session_dir", cfg.Database.SessionDir)
	v.SetDefault("server.host", cfg.Server.Host)
	v.SetDefault("server.port", cfg.Server.Port)
	v.SetDefault("server.api_key", cfg.Server.APIKey)
	v.SetDefault("server.secure_cookies", cfg.Server.SecureCookies)
	v.SetDefault("logging.level", cfg.Logging.Level)
	v.SetDefault("logging.format", cfg.Logging.Format)
	v.SetDefault("scan.mode", cfg.Scan.Mode)
	v.SetDefault("scan.phases", cfg.Scan.Phases)
	v.SetDefault("scan.tools", cfg.Scan.Tools)
	v.SetDefault("scan.concurrency", cfg.Scan.Concurrency)
	v.SetDefault("scan.rate_limit", cfg.Scan.RateLimit)
	v.SetDefault("cve.offline_path", cfg.CVE.OfflinePath)
	v.SetDefault("cve.enable_remote", cfg.CVE.EnableRemote)
	v.SetDefault("cve.cache_ttl", cfg.CVE.CacheTTL)
	v.SetDefault("cve.exploitdb_path", cfg.CVE.ExploitDBPath)
	v.SetDefault("cve.sources", cfg.CVE.Sources)
	v.SetDefault("power.providers.github_token", cfg.Power.Providers.GitHubToken)
	v.SetDefault("power.providers.shodan_api_key", cfg.Power.Providers.ShodanAPIKey)
	v.SetDefault("power.providers.securitytrails_api_key", cfg.Power.Providers.SecurityTrailsAPIKey)
	v.SetDefault("power.burp.base_url", cfg.Power.Burp.BaseURL)
	v.SetDefault("power.burp.api_key", cfg.Power.Burp.APIKey)
	v.SetDefault("power.burp.allowed_hosts", cfg.Power.Burp.AllowedHosts)
	v.SetDefault("power.callbacks.provider", cfg.Power.Callbacks.Provider)
	v.SetDefault("power.callbacks.interactsh_url", cfg.Power.Callbacks.InteractshURL)
	v.SetDefault("power.credentials.max_attempts_per_user", cfg.Power.Credentials.MaxAttemptsPerUser)
	v.SetDefault("power.credentials.delay_seconds", cfg.Power.Credentials.DelaySeconds)
	v.SetDefault("power.credentials.store_plaintext", cfg.Power.Credentials.StorePlaintext)
	v.SetDefault("power.active_validation.enabled", cfg.Power.ActiveValidation.Enabled)
	v.SetDefault("tools", cfg.Tools)
	v.SetDefault("plugins", cfg.Plugins)
}

func bindEnv(v *viper.Viper) {
	keys := []string{
		"llm.enabled", "llm.provider", "llm.base_url", "llm.api_key", "llm.model", "llm.max_tokens", "llm.temperature",
		"database.session_dir", "server.host", "server.port", "server.api_key", "server.secure_cookies",
		"logging.level", "logging.format",
		"scan.mode", "scan.phases", "scan.tools", "scan.concurrency", "scan.rate_limit",
		"cve.offline_path", "cve.enable_remote", "cve.cache_ttl", "cve.exploitdb_path", "cve.sources",
		"power.providers.github_token", "power.providers.shodan_api_key", "power.providers.securitytrails_api_key",
		"power.burp.base_url", "power.burp.api_key", "power.burp.allowed_hosts",
		"power.callbacks.provider", "power.callbacks.interactsh_url",
		"power.credentials.max_attempts_per_user", "power.credentials.delay_seconds", "power.credentials.store_plaintext",
		"power.active_validation.enabled",
		"plugins",
	}
	for _, key := range keys {
		_ = v.BindEnv(key)
	}
}

func getStringSlice(v *viper.Viper, key string) []string {
	values := v.GetStringSlice(key)
	if len(values) == 1 && strings.Contains(values[0], ",") {
		return splitCSV(values[0])
	}
	return values
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
