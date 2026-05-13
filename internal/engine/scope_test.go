package engine

import "testing"

func TestScopeChecker(t *testing.T) {
	checker, err := NewScopeChecker([]string{"example.com", "10.0.0.0/24", "*.app.test"}, []string{"admin.example.com", "10.0.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"https://example.com/login", true},
		{"admin.example.com", false},
		{"10.0.0.9", true},
		{"10.0.0.0/24", true},
		{"10.0.0.10", false},
		{"api.app.test", true},
		{"other.test", false},
	}
	for _, tt := range tests {
		got, _ := checker.IsInScope(tt.host)
		if got != tt.want {
			t.Fatalf("IsInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}
