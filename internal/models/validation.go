package models

import (
	"errors"
	"fmt"
	"strings"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

func (t FindingType) Valid() bool {
	switch t {
	case FindingTypeVulnerability, FindingTypeMisconfiguration, FindingTypeExposure, FindingTypeInfo:
		return true
	default:
		return false
	}
}

func (s SessionStatus) Valid() bool {
	switch s {
	case SessionStatusPending, SessionStatusRunning, SessionStatusCompleted, SessionStatusFailed, SessionStatusCancelled:
		return true
	default:
		return false
	}
}

func (m ScanMode) Valid() bool {
	switch m {
	case ScanModePassive, ScanModeActive, ScanModeStealth:
		return true
	default:
		return false
	}
}

func (f ReportFormat) Valid() bool {
	switch f {
	case ReportFormatMarkdown, ReportFormatHTML, ReportFormatPDF:
		return true
	default:
		return false
	}
}

func (m ReportMode) Valid() bool {
	switch m {
	case ReportModeExecutive, ReportModeTechnical:
		return true
	default:
		return false
	}
}

func (f Finding) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", f.ID)
	errs = appendRequired(errs, "session_id", f.SessionID)
	errs = appendRequired(errs, "target_id", f.TargetID)
	errs = appendRequired(errs, "tool_id", f.ToolID)
	errs = appendRequired(errs, "title", f.Title)
	if !f.Type.Valid() {
		errs = append(errs, fmt.Errorf("type %q is invalid", f.Type))
	}
	if !f.Severity.Valid() {
		errs = append(errs, fmt.Errorf("severity %q is invalid", f.Severity))
	}
	errs = appendRange(errs, "confidence", f.Confidence, 0, 1)
	errs = appendRange(errs, "cvss_score", f.CVSSScore, 0, 10)
	return errors.Join(errs...)
}

func (t Technology) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", t.ID)
	errs = appendRequired(errs, "target_id", t.TargetID)
	errs = appendRequired(errs, "name", t.Name)
	errs = appendRequired(errs, "source_tool", t.SourceTool)
	errs = appendRange(errs, "confidence", t.Confidence, 0, 1)
	return errors.Join(errs...)
}

func (t Target) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", t.ID)
	errs = appendRequired(errs, "session_id", t.SessionID)
	errs = appendRequired(errs, "host", t.Host)
	errs = appendRequired(errs, "protocol", t.Protocol)
	if t.Port < 0 || t.Port > 65535 {
		errs = append(errs, errors.New("port must be between 0 and 65535"))
	}
	for i, technology := range t.Technologies {
		if err := technology.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("technologies[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (s Session) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", s.ID)
	errs = appendRequired(errs, "name", s.Name)
	errs = appendRequired(errs, "target_input", s.TargetInput)
	if !s.Status.Valid() {
		errs = append(errs, fmt.Errorf("status %q is invalid", s.Status))
	}
	if !s.Mode.Valid() {
		errs = append(errs, fmt.Errorf("mode %q is invalid", s.Mode))
	}
	if s.TargetCount < 0 {
		errs = append(errs, errors.New("target_count must be non-negative"))
	}
	if s.FindingCount < 0 {
		errs = append(errs, errors.New("finding_count must be non-negative"))
	}
	return errors.Join(errs...)
}

func (m CVEMatch) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", m.ID)
	if strings.TrimSpace(m.FindingID) == "" && strings.TrimSpace(m.TechnologyID) == "" {
		errs = append(errs, errors.New("finding_id or technology_id is required"))
	}
	errs = appendRequired(errs, "cve_id", m.CVEID)
	errs = appendRequired(errs, "source", m.Source)
	errs = appendRange(errs, "cvss_v3_score", m.CVSSv3Score, 0, 10)
	errs = appendRange(errs, "confidence_score", m.ConfidenceScore, 0, 1)
	return errors.Join(errs...)
}

func (v AttackVector) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", v.ID)
	errs = appendRequired(errs, "session_id", v.SessionID)
	errs = appendRequired(errs, "title", v.Title)
	if !v.Severity.Valid() {
		errs = append(errs, fmt.Errorf("severity %q is invalid", v.Severity))
	}
	errs = appendRange(errs, "confidence", v.Confidence, 0, 1)
	for i, step := range v.Steps {
		if err := step.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("steps[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (s AttackStep) Validate() error {
	var errs []error
	if s.Order < 1 {
		errs = append(errs, errors.New("order must be greater than zero"))
	}
	errs = appendRequired(errs, "description", s.Description)
	return errors.Join(errs...)
}

func (r ToolRun) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", r.ID)
	errs = appendRequired(errs, "session_id", r.SessionID)
	errs = appendRequired(errs, "tool_id", r.ToolID)
	if r.DurationMS < 0 {
		errs = append(errs, errors.New("duration_ms must be non-negative"))
	}
	if r.FindingCount < 0 {
		errs = append(errs, errors.New("finding_count must be non-negative"))
	}
	return errors.Join(errs...)
}

func (r Report) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", r.ID)
	errs = appendRequired(errs, "session_id", r.SessionID)
	errs = appendRequired(errs, "title", r.Title)
	if !r.Format.Valid() {
		errs = append(errs, fmt.Errorf("format %q is invalid", r.Format))
	}
	if !r.Mode.Valid() {
		errs = append(errs, fmt.Errorf("mode %q is invalid", r.Mode))
	}
	for i, section := range r.Sections {
		if err := section.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("sections[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (s ReportSection) Validate() error {
	var errs []error
	errs = appendRequired(errs, "id", string(s.ID))
	errs = appendRequired(errs, "title", s.Title)
	if s.Position < 1 {
		errs = append(errs, errors.New("position must be greater than zero"))
	}
	return errors.Join(errs...)
}

func appendRequired(errs []error, field, value string) []error {
	if strings.TrimSpace(value) == "" {
		return append(errs, fmt.Errorf("%s is required", field))
	}
	return errs
}

func appendRange(errs []error, field string, value, min, max float64) []error {
	if value < min || value > max {
		return append(errs, fmt.Errorf("%s must be between %.1f and %.1f", field, min, max))
	}
	return errs
}
