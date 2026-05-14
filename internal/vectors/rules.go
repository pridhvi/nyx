package vectors

import (
	"fmt"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

type Rule struct {
	ID             string
	Title          string
	Description    string
	OWASPCategory  string
	Severity       models.Severity
	BaseConfidence float64
	Conditions     []Condition
	ChainTemplate  []StepTemplate
}

type Condition struct {
	ToolID       string
	FindingType  models.FindingType
	SeverityMin  models.Severity
	URLContains  string
	TagContains  string
	ParameterSet bool
}

type StepTemplate struct {
	Description   string
	ToolSuggested string
}

type Engine struct {
	Rules []Rule
}

func NewEngine() Engine {
	return Engine{Rules: DefaultRules}
}

func (e Engine) Generate(sessionID string, findings []models.Finding, cves []models.CVEMatch) []models.AttackVector {
	if len(e.Rules) == 0 {
		e.Rules = DefaultRules
	}
	var vectors []models.AttackVector
	seen := map[string]bool{}
	for _, rule := range e.Rules {
		matches, ok := matchRule(rule, findings)
		if !ok {
			continue
		}
		vector := vectorFromRule(sessionID, rule, matches)
		key := vector.Title + ":" + strings.Join(vector.PrereqFindingIDs, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		vectors = append(vectors, vector)
	}
	for _, cve := range cves {
		if !cve.ExploitAvailable || cve.CVSSv3Score < 7 {
			continue
		}
		vector := vectorFromCVE(sessionID, cve)
		key := vector.Title + ":" + strings.Join(vector.PrereqFindingIDs, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		vectors = append(vectors, vector)
	}
	return vectors
}

func matchRule(rule Rule, findings []models.Finding) ([]models.Finding, bool) {
	var matches []models.Finding
	used := map[string]bool{}
	for _, condition := range rule.Conditions {
		found := false
		for _, finding := range findings {
			if used[finding.ID] {
				continue
			}
			if !conditionMatches(condition, finding) {
				continue
			}
			matches = append(matches, finding)
			used[finding.ID] = true
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	return matches, true
}

func conditionMatches(condition Condition, finding models.Finding) bool {
	if condition.ToolID != "" && finding.ToolID != condition.ToolID {
		return false
	}
	if condition.FindingType != "" && finding.Type != condition.FindingType {
		return false
	}
	if condition.SeverityMin != "" && severityRank(finding.Severity) < severityRank(condition.SeverityMin) {
		return false
	}
	if condition.URLContains != "" && !strings.Contains(strings.ToLower(finding.URL), strings.ToLower(condition.URLContains)) {
		return false
	}
	if condition.TagContains != "" && !hasTag(finding.Tags, condition.TagContains) {
		return false
	}
	if condition.ParameterSet && strings.TrimSpace(finding.Parameter) == "" {
		return false
	}
	return true
}

func vectorFromRule(sessionID string, rule Rule, findings []models.Finding) models.AttackVector {
	prereqs := make([]string, 0, len(findings))
	for _, finding := range findings {
		prereqs = append(prereqs, finding.ID)
	}
	steps := make([]models.AttackStep, 0, len(rule.ChainTemplate))
	for i, template := range rule.ChainTemplate {
		step := models.AttackStep{
			Order:         i + 1,
			Description:   renderStep(template.Description, findings),
			ToolSuggested: template.ToolSuggested,
		}
		if i < len(findings) {
			step.FindingID = findings[i].ID
		}
		steps = append(steps, step)
	}
	return models.AttackVector{
		ID:               models.NewID(),
		SessionID:        sessionID,
		Title:            rule.Title,
		Description:      rule.Description,
		Narrative:        narrativeFor(rule, findings),
		OWASPCategory:    rule.OWASPCategory,
		Severity:         rule.Severity,
		Confidence:       scoreConfidence(rule.BaseConfidence, findings),
		Steps:            steps,
		PrereqFindingIDs: prereqs,
		LLMReviewed:      false,
		CreatedAt:        time.Now().UTC(),
	}
}

func vectorFromCVE(sessionID string, cve models.CVEMatch) models.AttackVector {
	prereqs := []string{}
	if cve.FindingID != "" {
		prereqs = append(prereqs, cve.FindingID)
	}
	return models.AttackVector{
		ID:               models.NewID(),
		SessionID:        sessionID,
		Title:            "Exploit candidate for " + cve.CVEID,
		Description:      cve.Description,
		Narrative:        "A high-severity CVE with exploit availability was correlated to scan evidence.",
		OWASPCategory:    "A06:2021 Vulnerable and Outdated Components",
		Severity:         severityForScore(cve.CVSSv3Score),
		Confidence:       clamp(cve.ConfidenceScore),
		PrereqFindingIDs: prereqs,
		Steps: []models.AttackStep{
			{Order: 1, Description: "Confirm the affected component and version for " + cve.CVEID + ".", FindingID: cve.FindingID},
			{Order: 2, Description: "Validate exploitability within the authorized scope.", ToolSuggested: "nuclei -id " + strings.ToLower(cve.CVEID)},
			{Order: 3, Description: "Document remediation and patch availability.", ToolSuggested: "nox sessions findings <session-id>"},
		},
		CreatedAt: time.Now().UTC(),
	}
}

func renderStep(template string, findings []models.Finding) string {
	if len(findings) == 0 {
		return template
	}
	finding := findings[0]
	replacer := strings.NewReplacer(
		"{url}", finding.URL,
		"{parameter}", finding.Parameter,
		"{title}", finding.Title,
	)
	return replacer.Replace(template)
}

func narrativeFor(rule Rule, findings []models.Finding) string {
	if len(findings) == 0 {
		return rule.Description
	}
	return fmt.Sprintf("%s Evidence starts with %s from %s.", rule.Description, findings[0].Title, findings[0].ToolID)
}

func scoreConfidence(base float64, findings []models.Finding) float64 {
	score := base
	for _, finding := range findings {
		if finding.Confidence > 0 {
			score += (finding.Confidence - 0.5) * 0.05
		}
		if severityRank(finding.Severity) >= severityRank(models.SeverityHigh) {
			score += 0.02
		}
	}
	return clamp(score)
}

func severityForScore(score float64) models.Severity {
	switch {
	case score >= 9:
		return models.SeverityCritical
	case score >= 7:
		return models.SeverityHigh
	case score >= 4:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func severityRank(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	case models.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want || strings.Contains(tag, want) {
			return true
		}
	}
	return false
}

var DefaultRules = []Rule{
	{
		ID:             "xss-no-csp",
		Title:          "Reflected XSS with missing Content-Security-Policy",
		Description:    "A reflected XSS finding is paired with a missing CSP, increasing exploit reliability and impact.",
		OWASPCategory:  "A03:2021 - Injection",
		Severity:       models.SeverityHigh,
		BaseConfidence: 0.85,
		Conditions: []Condition{
			{ToolID: "dalfox", FindingType: models.FindingTypeVulnerability, ParameterSet: true},
			{ToolID: "security-headers", TagContains: "missing-csp"},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Use the reflected XSS parameter {parameter}.", ToolSuggested: "dalfox url {url}"},
			{Description: "Confirm CSP is missing and does not constrain script execution.", ToolSuggested: "nox sessions findings <session-id>"},
			{Description: "Demonstrate impact with a scoped proof of concept payload."},
		},
	},
	{
		ID:             "ssrf-cloud-metadata",
		Title:          "SSRF path to cloud metadata access",
		Description:    "An SSRF finding can be used to probe cloud metadata services from the target environment.",
		OWASPCategory:  "A10:2021 - Server-Side Request Forgery",
		Severity:       models.SeverityCritical,
		BaseConfidence: 0.82,
		Conditions: []Condition{
			{TagContains: "ssrf", FindingType: models.FindingTypeVulnerability},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Replay the SSRF parameter {parameter} with an internal metadata URL.", ToolSuggested: "ssrfmap"},
			{Description: "Confirm whether cloud metadata or internal service data is reachable."},
			{Description: "Document network egress controls and metadata protection gaps."},
		},
	},
	{
		ID:             "weak-jwt-secret",
		Title:          "Weak JWT signing controls enable token forgery",
		Description:    "JWT validation weakness can allow privilege escalation through forged or unsigned tokens.",
		OWASPCategory:  "A02:2021 - Cryptographic Failures",
		Severity:       models.SeverityCritical,
		BaseConfidence: 0.88,
		Conditions: []Condition{
			{ToolID: "jwt-tool", TagContains: "weak-secret"},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Confirm the JWT signing weakness with jwt_tool.", ToolSuggested: "jwt_tool"},
			{Description: "Forge a scoped low-risk token claim change."},
			{Description: "Validate authorization impact without accessing unauthorized data."},
		},
	},
	{
		ID:             "sqli-unauth",
		Title:          "Unauthenticated SQL injection path",
		Description:    "A SQL injection finding on a reachable endpoint can support database enumeration inside the authorized scope.",
		OWASPCategory:  "A03:2021 - Injection",
		Severity:       models.SeverityCritical,
		BaseConfidence: 0.92,
		Conditions: []Condition{
			{ToolID: "sqlmap", FindingType: models.FindingTypeVulnerability, ParameterSet: true},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Confirm injectable parameter {parameter} with sqlmap.", ToolSuggested: "sqlmap -u {url} --batch --risk 1 --level 1"},
			{Description: "Enumerate schema metadata inside the authorized scope.", ToolSuggested: "sqlmap --dbs"},
			{Description: "Document affected queries and parameterized-query remediation."},
		},
	},
	{
		ID:             "admin-default-auth",
		Title:          "Exposed admin surface with weak/default auth indicators",
		Description:    "An exposed administrative path is paired with weak/default authentication indicators.",
		OWASPCategory:  "A07:2021 - Identification and Authentication Failures",
		Severity:       models.SeverityHigh,
		BaseConfidence: 0.78,
		Conditions: []Condition{
			{TagContains: "admin-panel"},
			{TagContains: "default-credentials"},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Open the discovered administrative path {url}."},
			{Description: "Validate weak/default authentication indicators without brute force."},
			{Description: "Recommend access control hardening and credential rotation."},
		},
	},
	{
		ID:             "cors-wildcard-credentials",
		Title:          "CORS wildcard credentials attack path",
		Description:    "Permissive CORS with credentials can expose authenticated browser responses to an attacker-controlled origin.",
		OWASPCategory:  "A05:2021 - Security Misconfiguration",
		Severity:       models.SeverityHigh,
		BaseConfidence: 0.84,
		Conditions: []Condition{
			{ToolID: "cors-check", TagContains: "cors-wildcard-credentials"},
		},
		ChainTemplate: []StepTemplate{
			{Description: "Host a controlled origin and issue credentialed requests to {url}."},
			{Description: "Confirm whether sensitive authenticated data is readable from the browser."},
			{Description: "Restrict allowed origins and remove credentialed wildcard behavior."},
		},
	},
}
