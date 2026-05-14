package config

import (
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
	if cfg.Server.Host != "127.0.0.1" || cfg.Server.Port != 8080 {
		t.Fatalf("unexpected server defaults: %#v", cfg.Server)
	}
	if cfg.LLM.Model != "llama3:8b" {
		t.Fatalf("unexpected LLM default: %#v", cfg.LLM)
	}
}

func TestEnvOverridesConfig(t *testing.T) {
	t.Setenv("NOX_LLM_BASE_URL", "http://localhost:11434/v1")
	t.Setenv("NOX_SESSION_DIR", "/tmp/nox-sessions")
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM.BaseURL != "http://localhost:11434/v1" {
		t.Fatalf("expected env LLM URL override, got %q", cfg.LLM.BaseURL)
	}
	if cfg.Database.SessionDir != "/tmp/nox-sessions" {
		t.Fatalf("expected env session dir override, got %q", cfg.Database.SessionDir)
	}
}
