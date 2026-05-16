package report

import (
	"encoding/json"
	"strings"

	"github.com/pridhvi/nox/internal/models"
)

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules,omitempty"`
}
type sarifRule struct {
	ID   string       `json:"id"`
	Name string       `json:"name,omitempty"`
	Help sarifMessage `json:"help,omitempty"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func renderSARIF(report models.Report) []byte {
	var findings []models.Finding
	_ = json.Unmarshal([]byte(report.Summary), &findings)
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, finding := range findings {
		if finding.Status != "" && finding.Status != "confirmed" {
			continue
		}
		ruleID := finding.ToolID
		if len(finding.Tags) > 0 {
			ruleID += "/" + finding.Tags[len(finding.Tags)-1]
		}
		uri, line := sarifLocationFromFinding(finding)
		rules[ruleID] = sarifRule{ID: ruleID, Name: finding.Title, Help: sarifMessage{Text: finding.Remediation}}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMessage{Text: firstText(finding.Description, finding.Title)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
				Region:           sarifRegion{StartLine: line},
			}}},
		})
	}
	var ruleList []sarifRule
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	body, _ := json.MarshalIndent(sarifReport{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "Nox", Rules: ruleList}}, Results: results}}}, "", "  ")
	return body
}

func sarifLocationFromFinding(finding models.Finding) (string, int) {
	value := strings.TrimPrefix(finding.URL, "file://")
	line := 0
	if idx := strings.Index(value, "#L"); idx >= 0 {
		line = atoiSafe(value[idx+2:])
		value = value[:idx]
	}
	return value, line
}

func sarifLevel(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func atoiSafe(value string) int {
	n := 0
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
