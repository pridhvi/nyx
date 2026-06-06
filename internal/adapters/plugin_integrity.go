package adapters

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func PluginBinarySHA256(binary string) (string, error) {
	path, err := resolvePluginBinary(binary)
	if err != nil {
		return "", err
	}
	return pluginBinaryPathSHA256(path)
}

func VerifiedPluginBinaryPath(binary, want string) (string, error) {
	path, err := resolvePluginBinary(binary)
	if err != nil {
		return "", err
	}
	if err := verifyPluginBinaryPathSHA256(path, want); err != nil {
		return "", err
	}
	return path, nil
}

func VerifyPluginBinarySHA256(binary, want string) error {
	_, err := VerifiedPluginBinaryPath(binary, want)
	return err
}

func verifyPluginBinaryPathSHA256(path, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return fmt.Errorf("plugin binary integrity check failed: expected sha256 is required")
	}
	got, err := pluginBinaryPathSHA256(path)
	if err != nil {
		return fmt.Errorf("plugin binary integrity check failed: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("plugin binary integrity check failed: sha256 mismatch")
	}
	return nil
}

func pluginBinaryPathSHA256(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- plugin binary path is validated before registration and rechecked before execution.
	if err != nil {
		return "", fmt.Errorf("open plugin binary for hashing: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash plugin binary: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func resolvePluginBinary(binary string) (string, error) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return "", fmt.Errorf("plugin binary is required")
	}
	if filepath.IsAbs(binary) || strings.Contains(binary, string(filepath.Separator)) {
		return binary, nil
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("plugin binary %q was not found on PATH: %w", binary, err)
	}
	return path, nil
}
