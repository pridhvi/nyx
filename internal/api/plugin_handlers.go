package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	plugins, err := store.ListPlugins(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, plugins)
}

type pluginRequest struct {
	Name        string `json:"name"`
	Binary      string `json:"binary"`
	Phase       string `json:"phase"`
	Description string `json:"description"`
	HomepageURL string `json:"homepage_url"`
	Enabled     *bool  `json:"enabled"`
}

func (s *Server) globalPluginsPath() string {
	return filepath.Join(s.stateDir(), "plugins.json")
}

func (s *Server) pluginBinDir() string {
	return filepath.Join(s.stateDir(), "plugins", "bin")
}

func (s *Server) requireConfiguredAPIKey(w http.ResponseWriter, reason string) bool {
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": reason})
	return false
}

func (s *Server) listGlobalPlugins(w http.ResponseWriter, r *http.Request) {
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, plugins)
}

func (s *Server) createGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plugin, err := pluginFromRequest(req, models.NewID(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	plugins = append(plugins, plugin)
	if err := s.writeGlobalPlugins(plugins); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, plugin)
}

func (s *Server) updateGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("plugin_id"))
	for i := range plugins {
		if plugins[i].ID != id {
			continue
		}
		var req pluginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			plugins[i].Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Binary) != "" {
			if err := validatePluginBinary(req.Binary); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			digest, err := adapters.PluginBinarySHA256(req.Binary)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			plugins[i].Binary = strings.TrimSpace(req.Binary)
			plugins[i].SHA256 = digest
		}
		if strings.TrimSpace(req.Phase) != "" {
			if err := validatePluginPhase(req.Phase); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			plugins[i].Phase = strings.TrimSpace(req.Phase)
		}
		if req.Description != "" {
			plugins[i].Description = strings.TrimSpace(req.Description)
		}
		if req.HomepageURL != "" {
			plugins[i].HomepageURL = strings.TrimSpace(req.HomepageURL)
		}
		if req.Enabled != nil {
			plugins[i].Enabled = *req.Enabled
		}
		plugins[i].UpdatedAt = time.Now().UTC()
		if err := s.writeGlobalPlugins(plugins); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, plugins[i])
		return
	}
	writeDBError(w, db.ErrNotFound)
}

func (s *Server) deleteGlobalPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "global plugin management requires API key authentication") {
		return
	}
	plugins, err := s.readGlobalPlugins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("plugin_id"))
	next := plugins[:0]
	deleted := false
	for _, plugin := range plugins {
		if plugin.ID == id {
			deleted = true
			continue
		}
		next = append(next, plugin)
	}
	if !deleted {
		writeDBError(w, db.ErrNotFound)
		return
	}
	if err := s.writeGlobalPlugins(next); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": id})
}

func (s *Server) uploadPluginBinary(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "plugin upload requires API key authentication") {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPluginUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil { // #nosec G120 -- request body is capped by MaxBytesReader above.
		writeRequestBodyError(w, err)
		return
	}
	file, header, err := r.FormFile("binary")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	if err := os.MkdirAll(s.pluginBinDir(), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := safePluginFilename(header.Filename)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = "plugin-" + models.NewID()
	}
	path := filepath.Join(s.pluginBinDir(), name)
	if _, err := os.Stat(path); err == nil {
		path = filepath.Join(s.pluginBinDir(), models.NewID()+"-"+name)
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700) // #nosec G302,G304 -- uploaded plugin binaries must be owner-executable and path is constrained to pluginBinDir.
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer out.Close()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hash), file); err != nil {
		writeRequestBodyError(w, err)
		return
	}
	writeJSON(w, map[string]string{"binary": path, "sha256": hex.EncodeToString(hash.Sum(nil))})
}

func safePluginFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Server) readGlobalPlugins() ([]models.PluginRecord, error) {
	body, err := os.ReadFile(s.globalPluginsPath())
	if errors.Is(err, os.ErrNotExist) {
		return []models.PluginRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var plugins []models.PluginRecord
	if err := json.Unmarshal(body, &plugins); err != nil {
		return nil, err
	}
	if plugins == nil {
		plugins = []models.PluginRecord{}
	}
	return plugins, nil
}

func (s *Server) writeGlobalPlugins(plugins []models.PluginRecord) error {
	if err := os.MkdirAll(s.stateDir(), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.globalPluginsPath(), body, 0o600)
}

func (s *Server) enabledGlobalPlugins() []models.PluginRecord {
	plugins, _ := s.readGlobalPlugins()
	var out []models.PluginRecord
	for _, plugin := range plugins {
		if plugin.Enabled {
			out = append(out, plugin)
		}
	}
	return out
}

func pluginFromRequest(req pluginRequest, id string, now time.Time) (models.PluginRecord, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return models.PluginRecord{}, fmt.Errorf("plugin name is required")
	}
	binary := strings.TrimSpace(req.Binary)
	if err := validatePluginBinary(binary); err != nil {
		return models.PluginRecord{}, err
	}
	digest, err := adapters.PluginBinarySHA256(binary)
	if err != nil {
		return models.PluginRecord{}, err
	}
	phase := strings.TrimSpace(req.Phase)
	if phase == "" {
		phase = string(adapters.PhaseVulnScan)
	}
	if err := validatePluginPhase(phase); err != nil {
		return models.PluginRecord{}, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return models.PluginRecord{ID: id, Name: name, Binary: binary, SHA256: digest, Phase: phase, Description: strings.TrimSpace(req.Description), HomepageURL: strings.TrimSpace(req.HomepageURL), Enabled: enabled, CreatedAt: now, UpdatedAt: now}, nil
}

func validatePluginPhase(phase string) error {
	switch adapters.Phase(strings.TrimSpace(phase)) {
	case adapters.PhaseRecon, adapters.PhaseFingerprint, adapters.PhaseEnumerate, adapters.PhaseVulnScan:
		return nil
	default:
		return fmt.Errorf("unsupported plugin phase %q", phase)
	}
}

func (s *Server) upsertPlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "session plugin management requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Binary = strings.TrimSpace(req.Binary)
	if req.Binary == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("binary is required"))
		return
	}
	if err := validatePluginBinary(req.Binary); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	digest, err := adapters.PluginBinarySHA256(req.Binary)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(req.Binary), filepath.Ext(req.Binary))
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now().UTC()
	plugin := models.PluginRecord{ID: models.NewID(), Name: name, Binary: req.Binary, SHA256: digest, Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	if err := store.UpsertPlugin(r.Context(), plugin); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, plugin)
}

func (s *Server) updatePlugin(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "session plugin management requires API key authentication") {
		return
	}
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	plugins, err := store.ListPlugins(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	var existing *models.PluginRecord
	for i := range plugins {
		if plugins[i].ID == r.PathValue("plugin_id") {
			existing = &plugins[i]
			break
		}
	}
	if existing == nil {
		writeDBError(w, db.ErrNotFound)
		return
	}
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Binary) != "" {
		binary := strings.TrimSpace(req.Binary)
		if err := validatePluginBinary(binary); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		digest, err := adapters.PluginBinarySHA256(binary)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		existing.Binary = binary
		existing.SHA256 = digest
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := store.UpsertPlugin(r.Context(), *existing); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, existing)
}

func validatePluginBinary(binary string) error {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return fmt.Errorf("binary is required")
	}
	if strings.ContainsAny(binary, "\x00\r\n") || strings.Contains(binary, " ") {
		return fmt.Errorf("plugin binary must be a single executable path or PATH-resolvable command")
	}
	if filepath.IsAbs(binary) || strings.Contains(binary, string(filepath.Separator)) {
		info, err := os.Stat(binary)
		if err != nil {
			return fmt.Errorf("plugin binary is not accessible: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("plugin binary points to a directory")
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("plugin binary is not executable")
		}
		return nil
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("plugin binary %q was not found on PATH", binary)
	}
	return nil
}
