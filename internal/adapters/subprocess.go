package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type PluginRequest struct {
	Version           string              `json:"version"`
	SessionID         string              `json:"session_id"`
	Target            models.Target       `json:"target"`
	PriorFindings     []models.Finding    `json:"prior_findings"`
	PriorTechnologies []models.Technology `json:"prior_technologies"`
	Config            map[string]string   `json:"config"`
}

type PluginResponse struct {
	Version      string              `json:"version"`
	Findings     []models.Finding    `json:"findings"`
	NewTargets   []models.Target     `json:"new_targets"`
	Technologies []models.Technology `json:"technologies"`
	Error        *string             `json:"error"`
}

func RunPlugin(ctx context.Context, binary, expectedSHA256 string, req PluginRequest) (PluginResponse, error) {
	path, err := VerifiedPluginBinaryPath(binary, expectedSHA256)
	if err != nil {
		return PluginResponse{}, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return PluginResponse{}, err
	}
	cmd := exec.CommandContext(ctx, path) // #nosec G204 -- plugin binary path is registered, digest-pinned, and verified immediately before execution.
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return PluginResponse{}, fmt.Errorf("%s failed: %w: %s", binary, err, stderr.String())
	}
	var resp PluginResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return PluginResponse{}, err
	}
	if resp.Error != nil && *resp.Error != "" {
		return resp, fmt.Errorf("plugin returned error: %s", *resp.Error)
	}
	return resp, nil
}

type CommandResult struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	DurationMS int64
	Err        error
}

func RunCommand(ctx context.Context, timeout time.Duration, binary string, args ...string) CommandResult {
	started := time.Now().UTC()
	path, err := lookupCommand(binary)
	if err != nil {
		return CommandResult{
			Stderr:     err.Error(),
			ExitCode:   127,
			DurationMS: time.Since(started).Milliseconds(),
			Err:        err,
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- adapter binaries are registry/config resolved and args are built as discrete validated argv values.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			if stderr.Len() == 0 {
				stderr.WriteString(err.Error())
			}
		}
	}
	return CommandResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ExitCode:   exitCode,
		DurationMS: time.Since(started).Milliseconds(),
		Err:        err,
	}
}

func lookupCommand(binary string) (string, error) {
	if path, err := exec.LookPath(binary); err == nil {
		return path, nil
	} else if filepath.Base(binary) != binary {
		return "", err
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil || home == "" {
		return "", exec.ErrNotFound
	}
	for _, dir := range []string{
		filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".config", "composer", "vendor", "bin"),
	} {
		candidate := filepath.Join(dir, binary)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}
