package models

import "time"

type ReportFormat string

const (
	ReportFormatMarkdown ReportFormat = "md"
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatPDF      ReportFormat = "pdf"
	ReportFormatSARIF    ReportFormat = "sarif"
)

type ReportMode string

const (
	ReportModeExecutive ReportMode = "executive"
	ReportModeTechnical ReportMode = "technical"
)

type ReportSectionID string

const (
	ReportSectionExecutiveSummary ReportSectionID = "executive_summary"
	ReportSectionScopeMethodology ReportSectionID = "scope_methodology"
	ReportSectionHighFindings     ReportSectionID = "critical_high_findings"
	ReportSectionLowerFindings    ReportSectionID = "medium_low_findings"
	ReportSectionAttackVectors    ReportSectionID = "attack_vectors"
	ReportSectionCVEMatches       ReportSectionID = "cve_matches"
	ReportSectionRemediation      ReportSectionID = "remediation_roadmap"
	ReportSectionRawEvidence      ReportSectionID = "raw_tool_output"
)

type Report struct {
	ID              string          `json:"id"`
	SessionID       string          `json:"session_id"`
	Title           string          `json:"title"`
	Format          ReportFormat    `json:"format"`
	Mode            ReportMode      `json:"mode"`
	Summary         string          `json:"summary"`
	Sections        []ReportSection `json:"sections"`
	FindingIDs      []string        `json:"finding_ids"`
	CVEMatchIDs     []string        `json:"cve_match_ids"`
	AttackVectorIDs []string        `json:"attack_vector_ids"`
	GeneratedBy     string          `json:"generated_by"`
	LLMGenerated    bool            `json:"llm_generated"`
	CreatedAt       time.Time       `json:"created_at"`
}

type ReportSection struct {
	ID       ReportSectionID `json:"id"`
	Title    string          `json:"title"`
	Content  string          `json:"content"`
	Position int             `json:"position"`
}
