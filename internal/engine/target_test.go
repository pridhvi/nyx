package engine

import "testing"

func TestParseTargetInput(t *testing.T) {
	tests := []struct {
		input        string
		wantHost     string
		wantPort     int
		wantProtocol string
	}{
		{"https://example.com/path", "example.com", 443, "https"},
		{"http://example.com:8080", "example.com", 8080, "http"},
		{"example.org", "example.org", 443, "https"},
		{"10.0.0.0/24", "10.0.0.0/24", 443, "https"},
	}
	for _, tt := range tests {
		host, port, protocol := ParseTargetInput(tt.input)
		if host != tt.wantHost || port != tt.wantPort || protocol != tt.wantProtocol {
			t.Fatalf("ParseTargetInput(%q) = (%q, %d, %q), want (%q, %d, %q)", tt.input, host, port, protocol, tt.wantHost, tt.wantPort, tt.wantProtocol)
		}
	}
}
