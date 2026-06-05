package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/report"
)

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	records, err := db.ListSessions(r.Context(), s.cfg.SessionDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, records)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, session)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	_ = s.scanManager.Stop(sessionID)
	if err := db.DeleteSession(r.Context(), s.cfg.SessionDir, sessionID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, map[string]string{"deleted": sessionID})
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	targets, err := store.ListTargets(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, targets)
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	status, err := parseFindingStatus(r.URL.Query().Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	findings, err := store.ListFindings(r.Context(), session.ID, db.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		ToolID:   firstNonEmpty(r.URL.Query().Get("tool_id"), r.URL.Query().Get("tool")),
		Type:     r.URL.Query().Get("type"),
		Status:   status,
		Origin:   r.URL.Query().Get("origin"),
	})
	if err != nil {
		writeDBError(w, err)
		return
	}
	findings = filterFindings(findings, r.URL.Query().Get("cve"), r.URL.Query().Get("exploit"))
	if page, limit := pagination(r); limit > 0 {
		findings = paginate(findings, page, limit)
	}
	writeJSON(w, findings)
}

func (s *Server) listSourceFindings(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findings, err := store.ListSourceFindings(r.Context(), session.ID, db.SourceFindingFilter{Kind: r.URL.Query().Get("kind")})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, findings)
}

type sessionCompareResponse struct {
	BaseSessionID       string                  `json:"base_session_id"`
	CompareSessionID    string                  `json:"compare_session_id"`
	NewCount            int                     `json:"new_count"`
	ResolvedCount       int                     `json:"resolved_count"`
	SeverityChangeCount int                     `json:"severity_change_count"`
	NewFindings         []models.Finding        `json:"new_findings"`
	ResolvedFindings    []models.Finding        `json:"resolved_findings"`
	SeverityChanges     []sessionSeverityChange `json:"severity_changes"`
}

type sessionSeverityChange struct {
	Fingerprint string          `json:"fingerprint"`
	Title       string          `json:"title"`
	URL         string          `json:"url"`
	ToolID      string          `json:"tool_id"`
	From        models.Severity `json:"from"`
	To          models.Severity `json:"to"`
	FindingID   string          `json:"finding_id"`
}

func (s *Server) compareSessions(w http.ResponseWriter, r *http.Request) {
	compareID := r.PathValue("id")
	baseID := strings.TrimSpace(r.URL.Query().Get("base"))
	if baseID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("base session is required"))
		return
	}
	if baseID == compareID {
		writeError(w, http.StatusBadRequest, fmt.Errorf("base and comparison sessions must be different"))
		return
	}
	baseStore, err := db.OpenSession(r.Context(), s.cfg.SessionDir, baseID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer baseStore.Close()
	compareStore, err := db.OpenSession(r.Context(), s.cfg.SessionDir, compareID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer compareStore.Close()
	baseSession, err := baseStore.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	compareSession, err := compareStore.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	baseFindings, err := baseStore.ListFindings(r.Context(), baseSession.ID, db.FindingFilter{})
	if err != nil {
		writeDBError(w, err)
		return
	}
	compareFindings, err := compareStore.ListFindings(r.Context(), compareSession.ID, db.FindingFilter{})
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, compareFindingSets(baseSession.ID, compareSession.ID, baseFindings, compareFindings))
}

func compareFindingSets(baseSessionID, compareSessionID string, baseFindings, compareFindings []models.Finding) sessionCompareResponse {
	baseByFingerprint := make(map[string]models.Finding, len(baseFindings))
	compareByFingerprint := make(map[string]models.Finding, len(compareFindings))
	for _, finding := range baseFindings {
		baseByFingerprint[findingFingerprint(finding)] = finding
	}
	for _, finding := range compareFindings {
		compareByFingerprint[findingFingerprint(finding)] = finding
	}
	result := sessionCompareResponse{BaseSessionID: baseSessionID, CompareSessionID: compareSessionID}
	for fingerprint, finding := range compareByFingerprint {
		baseFinding, exists := baseByFingerprint[fingerprint]
		if !exists {
			result.NewFindings = append(result.NewFindings, finding)
			continue
		}
		if baseFinding.Severity != finding.Severity {
			result.SeverityChanges = append(result.SeverityChanges, sessionSeverityChange{
				Fingerprint: fingerprint,
				Title:       finding.Title,
				URL:         finding.URL,
				ToolID:      finding.ToolID,
				From:        baseFinding.Severity,
				To:          finding.Severity,
				FindingID:   finding.ID,
			})
		}
	}
	for fingerprint, finding := range baseByFingerprint {
		if _, exists := compareByFingerprint[fingerprint]; !exists {
			result.ResolvedFindings = append(result.ResolvedFindings, finding)
		}
	}
	result.NewCount = len(result.NewFindings)
	result.ResolvedCount = len(result.ResolvedFindings)
	result.SeverityChangeCount = len(result.SeverityChanges)
	return result
}

func findingFingerprint(finding models.Finding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(finding.Title)),
		strings.ToLower(strings.TrimSpace(finding.URL)),
		strings.ToLower(strings.TrimSpace(finding.ToolID)),
		strings.ToLower(strings.TrimSpace(string(finding.Type))),
	}
	return strings.Join(parts, "|")
}

type updateFindingRequest struct {
	Severity    models.Severity `json:"severity"`
	Remediation string          `json:"remediation"`
	Status      string          `json:"status"`
}

func (s *Server) updateFinding(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	findingID := r.PathValue("finding_id")
	var req updateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid severity %q", req.Severity))
		return
	}
	status, err := parseFindingStatus(req.Status)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := store.UpdateFindingWithAudit(r.Context(), session.ID, findingID, req.Severity, req.Remediation, status, "operator"); err != nil {
		writeDBError(w, err)
		return
	}
	findings, err := store.ListFindings(r.Context(), session.ID, db.FindingFilter{})
	if err != nil {
		writeDBError(w, err)
		return
	}
	for _, finding := range findings {
		if finding.ID == findingID {
			writeJSON(w, finding)
			return
		}
	}
	writeDBError(w, db.ErrNotFound)
}

func parseFindingStatus(value string) (models.FindingStatus, error) {
	status := models.FindingStatus(strings.TrimSpace(value))
	if status.Valid() {
		return status, nil
	}
	return "", fmt.Errorf("invalid finding status %q", value)
}

func (s *Server) listToolRuns(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	runs, err := store.ListToolRuns(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, runs)
}

func (s *Server) toolRunLog(stream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
		if err != nil {
			writeDBError(w, err)
			return
		}
		defer store.Close()
		session, err := store.GetSession(r.Context())
		if err != nil {
			writeDBError(w, err)
			return
		}
		runs, err := store.ListToolRuns(r.Context(), session.ID)
		if err != nil {
			writeDBError(w, err)
			return
		}
		var logPath string
		for _, run := range runs {
			if run.ID != r.PathValue("run_id") {
				continue
			}
			if stream == "stderr" {
				logPath = run.StderrPath
			} else {
				logPath = run.StdoutPath
			}
			break
		}
		if logPath == "" || !pathInside(filepath.Dir(store.Path()), logPath) {
			writeLogUnavailable(w)
			return
		}
		body, err := os.ReadFile(logPath) // #nosec G304 -- logPath is persisted by Nyx and checked with pathInside before reading.
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeLogUnavailable(w)
				return
			}
			writeDBError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(body)
	}
}

func writeLogUnavailable(w http.ResponseWriter) {
	writeJSONStatus(w, http.StatusNotFound, map[string]any{
		"available": false,
		"reason":    "log file not available",
	})
}

func pathInside(root, candidate string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func (s *Server) sessionStats(w http.ResponseWriter, r *http.Request) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return
	}
	defer store.Close()
	session, err := store.GetSession(r.Context())
	if err != nil {
		writeDBError(w, err)
		return
	}
	stats, err := store.Stats(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) listAttackVectors(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	vectors, err := store.ListAttackVectors(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, vectors)
}

func (s *Server) listAttackGraphEdges(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	edges, err := store.ListAttackGraphEdges(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, edges)
}

func (s *Server) listCVEs(w http.ResponseWriter, r *http.Request) {
	store, session, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	cves, err := store.ListCVEMatchesBySession(r.Context(), session.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, cves)
}

func (s *Server) generateReport(w http.ResponseWriter, r *http.Request) {
	store, _, ok := s.openSession(w, r)
	if !ok {
		return
	}
	defer store.Close()
	format := models.ReportFormat(firstNonEmpty(r.URL.Query().Get("format"), string(models.ReportFormatHTML)))
	mode := models.ReportMode(firstNonEmpty(r.URL.Query().Get("mode"), string(models.ReportModeTechnical)))
	includeSuppressed := true
	if raw := strings.TrimSpace(r.URL.Query().Get("include_suppressed")); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("include_suppressed must be true or false"))
			return
		}
		includeSuppressed = parsed
	}
	executiveSummary := strings.TrimSpace(r.URL.Query().Get("executive_summary"))
	if len(executiveSummary) > 4000 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("executive_summary must be 4000 characters or fewer"))
		return
	}
	artifact, err := report.Generate(r.Context(), store, report.Options{Format: format, Mode: mode, IncludeSuppressed: includeSuppressed, ExecutiveSummary: executiveSummary})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, artifact.Filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact.Content)
}

func (s *Server) openSession(w http.ResponseWriter, r *http.Request) (*db.Store, models.Session, bool) {
	store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, r.PathValue("id"))
	if err != nil {
		writeDBError(w, err)
		return nil, models.Session{}, false
	}
	session, err := store.GetSession(r.Context())
	if err != nil {
		store.Close()
		writeDBError(w, err)
		return nil, models.Session{}, false
	}
	return store, session, true
}

func validSeverity(severity models.Severity) bool {
	switch severity {
	case models.SeverityInfo, models.SeverityLow, models.SeverityMedium, models.SeverityHigh, models.SeverityCritical:
		return true
	default:
		return false
	}
}

func pagination(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 0 {
		limit = 0
	}
	if limit > 250 {
		limit = 250
	}
	return page, limit
}

func paginate[T any](items []T, page, limit int) []T {
	if limit <= 0 {
		return items
	}
	start := (page - 1) * limit
	if start >= len(items) {
		return []T{}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func filterFindings(findings []models.Finding, cveFilter, exploitFilter string) []models.Finding {
	if cveFilter == "" && exploitFilter == "" {
		return findings
	}
	wantCVE := parseQueryBool(cveFilter)
	wantExploit := parseQueryBool(exploitFilter)
	var out []models.Finding
	for _, finding := range findings {
		hasCVE := len(finding.CVEMatches) > 0
		hasExploit := false
		for _, match := range finding.CVEMatches {
			hasExploit = hasExploit || match.ExploitAvailable
		}
		if cveFilter != "" && hasCVE != wantCVE {
			continue
		}
		if exploitFilter != "" && hasExploit != wantExploit {
			continue
		}
		out = append(out, finding)
	}
	return out
}
