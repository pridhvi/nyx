package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	llmintel "github.com/pridhvi/nyx/internal/llm"
)

type llmRequest struct {
	Message string `json:"message"`
}

type llmModelsRequest struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
}

type llmModelsResponse struct {
	Models []string `json:"models"`
}

func (s *Server) llmModels(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfiguredAPIKey(w, "LLM model probing requires API key authentication") {
		return
	}
	var req llmModelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("base_url is required"))
		return
	}
	if err := llmintel.ValidateBaseURL(baseURL, s.cfg.LLMAllowedHosts); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, llmModelsURL(baseURL), nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	apiKey := firstNonEmpty(req.APIKey, s.cfg.AppConfig.LLM.APIKey, os.Getenv("NYX_LLM_API_KEY"))
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	var client interface {
		Do(*http.Request) (*http.Response, error)
	} = http.DefaultClient
	if s.cfg.HTTPClient != nil {
		client = httpClientAdapter{s.cfg.HTTPClient}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("llm models request failed: status %d", resp.StatusCode))
		return
	}
	var decoded struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	seen := map[string]bool{}
	var models []string
	for _, model := range decoded.Data {
		id := strings.TrimSpace(model.ID)
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	for _, id := range decoded.Models {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	if len(models) == 0 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("llm endpoint returned no models"))
		return
	}
	writeJSON(w, llmModelsResponse{Models: models})
}

type httpClientAdapter struct {
	client adapters.HTTPDoer
}

func (a httpClientAdapter) Do(req *http.Request) (*http.Response, error) {
	return a.client.Do(req)
}

func llmModelsURL(baseURL string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(base, "/models") {
		return base
	}
	if strings.HasSuffix(base, "/v1") {
		return base + "/models"
	}
	return base + "/v1/models"
}

func (s *Server) llmChat(w http.ResponseWriter, r *http.Request) {
	var req llmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("message is required"))
		return
	}
	s.runLLM(w, r, req.Message)
}

func (s *Server) llmAnalyse(w http.ResponseWriter, r *http.Request) {
	s.runLLM(w, r, "Review the completed scan. Summarize the highest-confidence risks, relevant CVEs, deterministic attack vectors, and safe follow-up checks.")
}

func (s *Server) llmHistory(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	history, err := store.ListLLMAnalyses(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, history)
}

func (s *Server) runLLM(w http.ResponseWriter, r *http.Request, prompt string) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	config := llmintel.ConfigFromSession(session)
	config.AllowedHosts = s.cfg.LLMAllowedHosts
	if !config.Configured() {
		writeError(w, http.StatusServiceUnavailable, llmintel.ErrNotConfigured)
		return
	}
	if err := llmintel.ValidateBaseURL(config.BaseURL, config.AllowedHosts); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	analysis, err := llmintel.NewAnalyst(store, nil, config).AnalyzeSession(r.Context(), session.ID, prompt)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, analysis)
}
