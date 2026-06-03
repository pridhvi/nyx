package adapters

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

func TestConfiguredPluginNormalizesResponse(t *testing.T) {
	binary := writePluginFixture(t, `{"version":"nyx.plugin.v1","findings":[{"type":"info","severity":"info","confidence":0.7,"title":"Plugin finding","description":"from fixture","url":"https://example.com"}],"technologies":[{"name":"fixture-tech","version":"1.0","category":"test","confidence":0.9}],"new_targets":[]}`)
	session := models.Session{ID: "session-1", Mode: models.ScanModeActive, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: "target-1", SessionID: session.ID, Host: "example.com", Protocol: "https", Port: 443}
	plugin := NewConfiguredPlugin(models.PluginRecord{
		ID:      "plugin-1",
		Name:    "fixture",
		Binary:  binary,
		SHA256:  mustPluginDigest(t, binary),
		Enabled: true,
	})

	output, err := plugin.Run(context.Background(), AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target:    target,
		Scope:     allowingScope{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.ToolRun.ExitCode != 0 || output.ToolRun.FindingCount != 1 {
		t.Fatalf("unexpected tool run: %#v", output.ToolRun)
	}
	if len(output.Findings) != 1 || output.Findings[0].ToolID != "plugin:fixture" || output.Findings[0].SessionID != session.ID {
		t.Fatalf("unexpected findings: %#v", output.Findings)
	}
	if len(output.Technologies) != 1 || output.Technologies[0].SourceTool != "plugin:fixture" || output.Technologies[0].TargetID != target.ID {
		t.Fatalf("unexpected technologies: %#v", output.Technologies)
	}
}

func TestConfiguredPluginRejectsDigestMismatchBeforeExecution(t *testing.T) {
	binary := writePluginFixture(t, `{"version":"nyx.plugin.v1","findings":[],"technologies":[],"new_targets":[]}`)
	plugin := NewConfiguredPlugin(models.PluginRecord{
		ID:      "plugin-1",
		Name:    "tampered",
		Binary:  binary,
		SHA256:  mustPluginDigest(t, binary),
		Enabled: true,
	})
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	session := models.Session{ID: "session-1", Mode: models.ScanModeActive, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: "target-1", SessionID: session.ID, Host: "example.com", Protocol: "https", Port: 443}

	output, err := plugin.Run(context.Background(), AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target:    target,
		Scope:     allowingScope{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.ToolRun.ExitCode == 0 || !strings.Contains(output.ToolRun.RawStderr, "sha256 mismatch") {
		t.Fatalf("expected digest mismatch before execution, got %#v", output.ToolRun)
	}
}

func TestConfiguredPluginMissingBinaryReturnsFailedToolRun(t *testing.T) {
	session := models.Session{ID: "session-1", Mode: models.ScanModeActive, CreatedAt: time.Now().UTC()}
	target := models.Target{ID: "target-1", SessionID: session.ID, Host: "example.com", Protocol: "https", Port: 443}
	plugin := NewConfiguredPlugin(models.PluginRecord{
		ID:      "plugin-1",
		Name:    "missing",
		Binary:  filepath.Join(t.TempDir(), "missing-plugin"),
		Enabled: true,
	})

	output, err := plugin.Run(context.Background(), AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target:    target,
		Scope:     allowingScope{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.ToolRun.ExitCode == 0 || output.ToolRun.RawStderr == "" {
		t.Fatalf("expected failed tool run, got %#v", output.ToolRun)
	}
}

func mustPluginDigest(t *testing.T, binary string) string {
	t.Helper()
	digest, err := PluginBinarySHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type allowingScope struct{}

func (allowingScope) IsInScope(string) (bool, string) {
	return true, ""
}

func writePluginFixture(t *testing.T, response string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}
	path := filepath.Join(t.TempDir(), "plugin-fixture")
	body := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + response + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
