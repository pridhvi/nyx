package adapters

import (
	"strings"
	"testing"
)

func TestValidateToolParametersAllowsSafeExtraArgs(t *testing.T) {
	err := ValidateToolParameters(map[string]map[string]any{
		"ffuf": {
			"wordlist":        "/tmp/words.txt",
			"timeout_seconds": 5,
			"extra_args":      []any{"-mc", "200,204", "-rate", "10"},
		},
		"sqlmap": {
			"level":      1,
			"risk":       1,
			"extra_args": []string{"--technique", "B"},
		},
	})
	if err != nil {
		t.Fatalf("expected safe extra args to validate: %v", err)
	}
}

func TestValidateToolParametersAllowsCommandInjectionSafetyGate(t *testing.T) {
	err := ValidateToolParameters(map[string]map[string]any{
		"command-injection-check": {
			"allow_command_injection":  true,
			"intentionally_vulnerable": true,
			"non_production":           true,
		},
	})
	if err != nil {
		t.Fatalf("expected command injection safety gate params to validate: %v", err)
	}
}

func TestValidateToolParametersAllowsStoredXSSSafetyGate(t *testing.T) {
	err := ValidateToolParameters(map[string]map[string]any{
		"stored-xss-check": {
			"allow_stored_xss":         true,
			"intentionally_vulnerable": true,
			"non_production":           true,
		},
	})
	if err != nil {
		t.Fatalf("expected stored XSS safety gate params to validate: %v", err)
	}
}

func TestValidateToolParametersAllowsCredentialValidationSafetyGate(t *testing.T) {
	err := ValidateToolParameters(map[string]map[string]any{
		"brute-force-check": {
			"allow_credential_validation": true,
			"intentionally_vulnerable":    true,
			"non_production":              true,
			"max_attempts":                1,
		},
	})
	if err != nil {
		t.Fatalf("expected credential validation safety gate params to validate: %v", err)
	}
}

func TestValidateToolParametersRejectsUnsafeExtraArgs(t *testing.T) {
	err := ValidateToolParameters(map[string]map[string]any{
		"sqlmap": {"extra_args": []any{"--os-shell"}},
	})
	if err == nil || !strings.Contains(err.Error(), "safe allow-list") {
		t.Fatalf("expected unsafe arg rejection, got %v", err)
	}
}

func TestValidateToolParametersRejectsUnknownParameter(t *testing.T) {
	err := ValidateToolParameterValues("ffuf", map[string]any{"shell": "nope"})
	if err == nil || !strings.Contains(err.Error(), "does not support parameter") {
		t.Fatalf("expected unsupported parameter rejection, got %v", err)
	}
}

func TestValidateToolParametersRejectsControlCharacters(t *testing.T) {
	err := ValidateExtraArgs("ffuf", []string{"-mc", "200\n--bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("expected control-character rejection, got %v", err)
	}
}
