package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDefaultAndLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Host != "127.0.0.1" || cfg.Server.Port != 6767 {
		t.Fatalf("unexpected server defaults: %#v", cfg.Server)
	}
	if !filepath.IsAbs(cfg.Database.SessionDir) {
		t.Fatalf("expected absolute session dir, got %q", cfg.Database.SessionDir)
	}
	if cfg.LLM.Model != "llama3:8b" {
		t.Fatalf("unexpected LLM default: %#v", cfg.LLM)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "text" {
		t.Fatalf("unexpected logging defaults: %#v", cfg.Logging)
	}
}

func TestRelativeSessionDirResolvesFromConfigDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  session_dir: data/sessions\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "data", "sessions")
	if cfg.Database.SessionDir != want {
		t.Fatalf("expected %q, got %q", want, cfg.Database.SessionDir)
	}
}

func TestTildeSessionDirResolvesToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n  session_dir: ~/.nyx/sessions\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".nyx", "sessions")
	if cfg.Database.SessionDir != want {
		t.Fatalf("expected %q, got %q", want, cfg.Database.SessionDir)
	}
}

func TestLoadNestedConfigListsAndToolPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := []byte(`
plugins = ["/opt/nyx/plugins"]

[llm]
enabled = true
base_url = "http://localhost:11434/v1"
model = "qwen2.5-coder"

[scan]
phases = ["recon", "fingerprint", "vuln"]
tools = ["http-probe", "nuclei-vuln"]
concurrency = 8

[cve]
sources = ["embedded", "nvd", "github-advisories", "exploitdb"]
cache_ttl = "12h"
exploitdb_path = "/opt/exploitdb/files_exploits.csv"

[tools]
nuclei = "/usr/local/bin/nuclei"
sqlmap = "/opt/sqlmap/sqlmap.py"
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LLM.Enabled || cfg.LLM.Model != "qwen2.5-coder" {
		t.Fatalf("unexpected LLM config: %#v", cfg.LLM)
	}
	if cfg.Scan.Concurrency != 8 || len(cfg.Scan.Phases) != 3 {
		t.Fatalf("unexpected scan config: %#v", cfg.Scan)
	}
	if cfg.CVE.ExploitDBPath == "" || len(cfg.CVE.Sources) != 4 {
		t.Fatalf("unexpected CVE config: %#v", cfg.CVE)
	}
	if cfg.Tools["nuclei"] == "" || cfg.Plugins[0] != "/opt/nyx/plugins" {
		t.Fatalf("unexpected tool/plugin config: tools=%#v plugins=%#v", cfg.Tools, cfg.Plugins)
	}
}

func TestEnvOverridesConfig(t *testing.T) {
	t.Setenv("NYX_LLM_BASE_URL", "http://localhost:11434/v1")
	t.Setenv("NYX_SESSION_DIR", "/tmp/nyx-sessions")
	t.Setenv("NYX_LOG_LEVEL", "debug")
	t.Setenv("NYX_LOG_FORMAT", "json")
	t.Setenv("NYX_SECURE_COOKIES", "true")
	t.Setenv("NYX_POWER_PROVIDERS_GITHUB_TOKEN", "ghp_secret")
	t.Setenv("NYX_POWER_BURP_API_KEY", "burp_secret")
	t.Setenv("NYX_POWER_ACTIVE_VALIDATION_ENABLED", "true")
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.BaseURL != "http://localhost:11434/v1" {
		t.Fatalf("expected env LLM URL override, got %q", cfg.LLM.BaseURL)
	}
	if cfg.Database.SessionDir != "/tmp/nyx-sessions" {
		t.Fatalf("expected env session dir override, got %q", cfg.Database.SessionDir)
	}
	if cfg.Logging.Level != "debug" || cfg.Logging.Format != "json" {
		t.Fatalf("expected env logging override, got %#v", cfg.Logging)
	}
	if !cfg.Server.SecureCookies {
		t.Fatalf("expected secure cookie env override, got %#v", cfg.Server)
	}
	if cfg.Power.Providers.GitHubToken != "ghp_secret" || cfg.Power.Burp.APIKey != "burp_secret" || !cfg.Power.ActiveValidation.Enabled {
		t.Fatalf("expected power env overrides, got %#v", cfg.Power)
	}
	redacted := cfg.Power.Redacted()
	if redacted.Providers.GitHubToken != "********" || redacted.Burp.APIKey != "********" {
		t.Fatalf("expected redacted power secrets, got %#v", redacted)
	}
}
