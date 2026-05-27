package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunCommandFindsUserGoBinWhenPathIsSparse(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, "go", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "nyx-test-tool")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho user-go-bin-tool\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/usr/bin:/bin")

	result := RunCommand(context.Background(), 5*time.Second, "nyx-test-tool")
	if result.ExitCode != 0 || result.Stdout != "user-go-bin-tool\n" {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
	}
}
