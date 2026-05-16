package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"":        slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for input, want := range tests {
		got, err := ParseLevel(input)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("expected invalid log level to fail")
	}
}

func TestConfigureJSON(t *testing.T) {
	var out bytes.Buffer
	if err := Configure(Options{Level: "debug", Format: "json", Output: &out}); err != nil {
		t.Fatal(err)
	}
	slog.Debug("configured", "component", "test")
	body := out.String()
	if !strings.Contains(body, `"level":"DEBUG"`) || !strings.Contains(body, `"component":"test"`) {
		t.Fatalf("expected JSON debug log, got %q", body)
	}
}
