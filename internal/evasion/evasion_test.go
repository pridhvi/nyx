package evasion

import (
	"testing"

	"github.com/pridhvi/nox/internal/models"
)

func TestNormalizeStealthProfile(t *testing.T) {
	options, policy, err := Normalize(models.ScanRunnerOptions{Concurrency: 8, PerToolConcurrency: 4, EvasionProfile: "stealth"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Concurrency != 1 || options.PerToolConcurrency != 1 {
		t.Fatalf("expected stealth concurrency clamp, got %#v", options)
	}
	if options.ToolDelayMS < 1000 || options.JitterMS < 250 || !options.AdaptiveBackoff {
		t.Fatalf("expected stealth pacing defaults, got %#v", options)
	}
	if policy.Profile != "stealth" || !policy.AdaptiveBackoff {
		t.Fatalf("unexpected policy: %#v", policy)
	}
}

func TestNormalizeRejectsBadProxyAndRedactsCredentials(t *testing.T) {
	if _, _, err := Normalize(models.ScanRunnerOptions{EvasionProfile: "custom", ProxyURL: "file:///tmp/proxy"}); err == nil {
		t.Fatal("expected invalid proxy URL to fail")
	}
	_, policy, err := Normalize(models.ScanRunnerOptions{EvasionProfile: "custom", ProxyURL: "http://user:pass@127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.ProxyURL != "http://%2A%2A%2A%2A%2A%2A%2A%2A@127.0.0.1:8080" {
		t.Fatalf("expected redacted proxy, got %q", policy.ProxyURL)
	}
}

func TestDetectBlockSignals(t *testing.T) {
	if signal, ok := DetectBlock(429, "slow down"); !ok || signal != "rate_limited" {
		t.Fatalf("expected rate limit signal, got %q %v", signal, ok)
	}
	if signal, ok := DetectBlock(200, "captcha required"); !ok || signal != "block_marker" {
		t.Fatalf("expected marker signal, got %q %v", signal, ok)
	}
}
