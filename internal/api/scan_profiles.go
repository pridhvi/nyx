package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

type scanProfileRecord struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Request     startScanRequest `json:"request"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type scanProfileRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Request     startScanRequest `json:"request"`
}

func (s *Server) listScanProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, profiles)
}

func (s *Server) createScanProfile(w http.ResponseWriter, r *http.Request) {
	var req scanProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("profile name is required"))
		return
	}
	if err := validateTools(req.Request.Tools); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := adapters.ValidateToolParameters(req.Request.ToolParameters); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Request = redactedScanProfileRequest(req.Request)
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	profile := scanProfileRecord{
		ID:          models.NewID(),
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		Request:     req.Request,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	profiles = append(profiles, profile)
	if err := s.writeScanProfiles(profiles); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, profile)
}

func redactedScanProfileRequest(req startScanRequest) startScanRequest {
	req.AuthHeaders = nil
	req.AuthCookies = nil
	req.AuthCookieHeader = ""
	req.AuthProfile = nil
	req.SecondaryAuthHeaders = nil
	req.SecondaryAuthCookies = nil
	req.SecondaryAuthCookieHeader = ""
	return req
}

func (s *Server) deleteScanProfile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("profile_id"))
	profiles, err := s.readScanProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	next := profiles[:0]
	deleted := false
	for _, profile := range profiles {
		if profile.ID == id {
			deleted = true
			continue
		}
		next = append(next, profile)
	}
	if !deleted {
		writeDBError(w, db.ErrNotFound)
		return
	}
	if err := s.writeScanProfiles(next); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": id})
}

func (s *Server) scanProfilesPath() string {
	return filepath.Join(s.stateDir(), "scan-profiles.json")
}

func (s *Server) readScanProfiles() ([]scanProfileRecord, error) {
	path := s.scanProfilesPath()
	body, err := os.ReadFile(path) // #nosec G304 -- scan profiles live under Nyx stateDir and are not target-controlled.
	if errors.Is(err, os.ErrNotExist) {
		return []scanProfileRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var profiles []scanProfileRecord
	if err := json.Unmarshal(body, &profiles); err != nil {
		return nil, err
	}
	if profiles == nil {
		profiles = []scanProfileRecord{}
	}
	return profiles, nil
}

func (s *Server) writeScanProfiles(profiles []scanProfileRecord) error {
	if err := os.MkdirAll(s.stateDir(), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.scanProfilesPath(), body, 0o600)
}
