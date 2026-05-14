package report

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

type Options struct {
	Format models.ReportFormat
	Mode   models.ReportMode
}

type Artifact struct {
	Report      models.Report
	Content     []byte
	ContentType string
	Filename    string
}

type Store interface {
	GetSession(ctx context.Context) (models.Session, error)
	ListTargets(ctx context.Context, sessionID string) ([]models.Target, error)
	ListFindings(ctx context.Context, sessionID string, filter db.FindingFilter) ([]models.Finding, error)
	ListCVEMatchesBySession(ctx context.Context, sessionID string) ([]models.CVEMatch, error)
	ListAttackVectors(ctx context.Context, sessionID string) ([]models.AttackVector, error)
	ListToolRuns(ctx context.Context, sessionID string) ([]models.ToolRun, error)
	ListLLMAnalyses(ctx context.Context, sessionID string) ([]models.LLMAnalysis, error)
	Stats(ctx context.Context, sessionID string) (db.SessionStats, error)
}

func Generate(ctx context.Context, store Store, options Options) (Artifact, error) {
	if options.Format == "" {
		options.Format = models.ReportFormatHTML
	}
	if options.Mode == "" {
		options.Mode = models.ReportModeTechnical
	}
	session, err := store.GetSession(ctx)
	if err != nil {
		return Artifact{}, err
	}
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	findings, err := store.ListFindings(ctx, session.ID, db.FindingFilter{})
	if err != nil {
		return Artifact{}, err
	}
	cves, err := store.ListCVEMatchesBySession(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	vectors, err := store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	runs, err := store.ListToolRuns(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	analyses, err := store.ListLLMAnalyses(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	stats, err := store.Stats(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	sections := buildSections(session, targets, findings, cves, vectors, runs, analyses, stats, options.Mode)
	report := models.Report{
		ID:              models.NewID(),
		SessionID:       session.ID,
		Title:           fmt.Sprintf("Nox report for %s", session.TargetInput),
		Format:          options.Format,
		Mode:            options.Mode,
		Summary:         sections[0].Content,
		Sections:        sections,
		FindingIDs:      findingIDs(findings),
		CVEMatchIDs:     cveIDs(cves),
		AttackVectorIDs: vectorIDs(vectors),
		GeneratedBy:     "nox",
		LLMGenerated:    len(analyses) > 0,
		CreatedAt:       time.Now().UTC(),
	}
	if err := report.Validate(); err != nil {
		return Artifact{}, err
	}
	content, contentType := render(report)
	return Artifact{
		Report:      report,
		Content:     content,
		ContentType: contentType,
		Filename:    safeFilename(session.ID, options.Format),
	}, nil
}

func buildSections(session models.Session, targets []models.Target, findings []models.Finding, cves []models.CVEMatch, vectors []models.AttackVector, runs []models.ToolRun, analyses []models.LLMAnalysis, stats db.SessionStats, mode models.ReportMode) []models.ReportSection {
	highs, lows := splitFindings(findings)
	sections := []models.ReportSection{
		{ID: models.ReportSectionExecutiveSummary, Title: "Executive Summary", Content: executiveSummary(session, findings, vectors, analyses, stats), Position: 1},
		{ID: models.ReportSectionScopeMethodology, Title: "Scope and Methodology", Content: scopeMethodology(session, targets, runs), Position: 2},
		{ID: models.ReportSectionHighFindings, Title: "Critical and High Findings", Content: findingsMarkdown(highs, true), Position: 3},
		{ID: models.ReportSectionLowerFindings, Title: "Medium, Low, and Informational Findings", Content: findingsMarkdown(lows, mode == models.ReportModeTechnical), Position: 4},
		{ID: models.ReportSectionAttackVectors, Title: "Attack Vectors", Content: vectorsMarkdown(vectors), Position: 5},
		{ID: models.ReportSectionCVEMatches, Title: "CVE Matches", Content: cvesMarkdown(cves), Position: 6},
		{ID: models.ReportSectionRemediation, Title: "Remediation Roadmap", Content: remediationMarkdown(findings, cves), Position: 7},
	}
	if mode == models.ReportModeTechnical {
		sections = append(sections, models.ReportSection{ID: models.ReportSectionRawEvidence, Title: "Raw Tool Output Appendix", Content: rawEvidenceMarkdown(findings, runs), Position: 8})
	}
	return sections
}

func executiveSummary(session models.Session, findings []models.Finding, vectors []models.AttackVector, analyses []models.LLMAnalysis, stats db.SessionStats) string {
	if len(analyses) > 0 {
		last := analyses[len(analyses)-1]
		for i := len(last.Messages) - 1; i >= 0; i-- {
			if last.Messages[i].Role == "assistant" && strings.TrimSpace(last.Messages[i].Content) != "" {
				return strings.TrimSpace(last.Messages[i].Content)
			}
		}
	}
	return fmt.Sprintf("The %s scan of %s produced %d findings across %d targets. Severity counts: critical=%d, high=%d, medium=%d, low=%d, info=%d. Nox generated %d deterministic attack vectors from persisted evidence.",
		session.Mode, session.TargetInput, stats.FindingCount, stats.TargetCount,
		stats.SeverityCounts[string(models.SeverityCritical)], stats.SeverityCounts[string(models.SeverityHigh)], stats.SeverityCounts[string(models.SeverityMedium)], stats.SeverityCounts[string(models.SeverityLow)], stats.SeverityCounts[string(models.SeverityInfo)], len(vectors))
}

func scopeMethodology(session models.Session, targets []models.Target, runs []models.ToolRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- Target input: %s\n- Mode: %s\n- In scope: %s\n- Out of scope: %s\n\n", session.TargetInput, session.Mode, strings.Join(session.InScope, ", "), strings.Join(session.OutOfScope, ", "))
	b.WriteString("Targets:\n")
	for _, target := range targets {
		fmt.Fprintf(&b, "- %s://%s:%d alive=%t discovered_by=%s\n", target.Protocol, target.Host, target.Port, target.IsAlive, target.DiscoveredBy)
	}
	b.WriteString("\nTools executed:\n")
	for _, run := range runs {
		fmt.Fprintf(&b, "- %s exit=%d findings=%d duration_ms=%d\n", run.ToolID, run.ExitCode, run.FindingCount, run.DurationMS)
	}
	return strings.TrimSpace(b.String())
}

func findingsMarkdown(findings []models.Finding, details bool) string {
	if len(findings) == 0 {
		return "No findings in this category."
	}
	sort.Slice(findings, func(i, j int) bool { return severityRank(findings[i].Severity) > severityRank(findings[j].Severity) })
	var b strings.Builder
	for _, finding := range findings {
		fmt.Fprintf(&b, "- **%s** [%s] %s (%s)\n", finding.Title, finding.Severity, finding.URL, finding.ToolID)
		if details {
			fmt.Fprintf(&b, "  - Description: %s\n  - Remediation: %s\n  - Evidence: %s\n", finding.Description, finding.Remediation, truncate(finding.EvidenceNormalized, 600))
		}
	}
	return strings.TrimSpace(b.String())
}

func vectorsMarkdown(vectors []models.AttackVector) string {
	if len(vectors) == 0 {
		return "No deterministic attack vectors were generated."
	}
	var b strings.Builder
	for _, vector := range vectors {
		fmt.Fprintf(&b, "- **%s** [%s, confidence %.2f]\n  %s\n", vector.Title, vector.Severity, vector.Confidence, vector.Narrative)
		for _, step := range vector.Steps {
			fmt.Fprintf(&b, "  %d. %s\n", step.Order, step.Description)
		}
	}
	return strings.TrimSpace(b.String())
}

func cvesMarkdown(cves []models.CVEMatch) string {
	if len(cves) == 0 {
		return "No CVE matches were correlated."
	}
	var b strings.Builder
	for _, cve := range cves {
		fmt.Fprintf(&b, "- **%s** CVSS %.1f patch=%t exploit=%t source=%s\n  %s\n", cve.CVEID, cve.CVSSv3Score, cve.PatchAvailable, cve.ExploitAvailable, cve.Source, cve.Description)
	}
	return strings.TrimSpace(b.String())
}

func remediationMarkdown(findings []models.Finding, cves []models.CVEMatch) string {
	if len(findings) == 0 && len(cves) == 0 {
		return "No remediation actions are required from the current evidence."
	}
	sort.Slice(findings, func(i, j int) bool { return severityRank(findings[i].Severity) > severityRank(findings[j].Severity) })
	var b strings.Builder
	for _, finding := range findings {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", finding.Severity, finding.Title, firstNonEmpty(finding.Remediation, "Review persisted evidence and remediate the confirmed issue."))
	}
	for _, cve := range cves {
		if cve.FixedVersion != "" {
			fmt.Fprintf(&b, "- Patch %s to fixed version %s.\n", cve.CVEID, cve.FixedVersion)
		}
	}
	return strings.TrimSpace(b.String())
}

func rawEvidenceMarkdown(findings []models.Finding, runs []models.ToolRun) string {
	var b strings.Builder
	for _, finding := range findings {
		fmt.Fprintf(&b, "### %s\n\nRaw evidence:\n\n```text\n%s\n```\n\n", finding.Title, truncate(finding.EvidenceRaw, 2000))
		if finding.HTTPEvidence != nil {
			fmt.Fprintf(&b, "HTTP request:\n\n```text\n%s\n```\n\nHTTP response:\n\n```text\n%s\n```\n\n", truncate(finding.HTTPEvidence.RequestRaw, 2000), truncate(finding.HTTPEvidence.ResponseRaw, 2000))
		}
	}
	for _, run := range runs {
		fmt.Fprintf(&b, "### Tool run: %s\n\nstdout:\n\n```text\n%s\n```\n\nstderr:\n\n```text\n%s\n```\n\n", run.ToolID, truncate(run.StdoutRaw, 2000), truncate(run.StderrRaw, 2000))
	}
	if strings.TrimSpace(b.String()) == "" {
		return "No raw evidence is available."
	}
	return strings.TrimSpace(b.String())
}

func render(report models.Report) ([]byte, string) {
	switch report.Format {
	case models.ReportFormatMarkdown:
		return []byte(renderMarkdown(report)), "text/markdown; charset=utf-8"
	case models.ReportFormatPDF:
		return renderPDF(renderMarkdown(report)), "application/pdf"
	default:
		return []byte(renderHTML(report)), "text/html; charset=utf-8"
	}
}

func renderMarkdown(report models.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\nGenerated: %s\n\n", report.Title, report.CreatedAt.Format(time.RFC3339))
	for _, section := range report.Sections {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", section.Title, section.Content)
	}
	return b.String()
}

func renderHTML(report models.Report) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>")
	b.WriteString(html.EscapeString(report.Title))
	b.WriteString("</title><style>body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;color:#17202a;line-height:1.55}h1,h2{color:#111827}pre{white-space:pre-wrap;background:#f3f6fa;padding:12px;border-radius:8px}section{border-top:1px solid #dde4ec;padding-top:18px;margin-top:24px}</style></head><body>")
	fmt.Fprintf(&b, "<h1>%s</h1><p>Generated: %s</p>", html.EscapeString(report.Title), report.CreatedAt.Format(time.RFC3339))
	for _, section := range report.Sections {
		fmt.Fprintf(&b, "<section><h2>%s</h2><pre>%s</pre></section>", html.EscapeString(section.Title), html.EscapeString(section.Content))
	}
	b.WriteString("</body></html>")
	return b.String()
}

func renderPDF(text string) []byte {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var content strings.Builder
	content.WriteString("BT /F1 10 Tf 50 780 Td 12 TL\n")
	for i, line := range lines {
		if i > 58 {
			break
		}
		fmt.Fprintf(&content, "(%s) Tj T*\n", pdfEscape(truncate(line, 95)))
	}
	content.WriteString("ET")
	stream := content.String()
	var b bytes.Buffer
	offsets := []int{}
	write := func(s string) {
		b.WriteString(s)
	}
	write("%PDF-1.4\n")
	offsets = append(offsets, b.Len())
	write("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	offsets = append(offsets, b.Len())
	write("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
	offsets = append(offsets, b.Len())
	write("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
	offsets = append(offsets, b.Len())
	write("4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
	offsets = append(offsets, b.Len())
	fmt.Fprintf(&b, "5 0 obj << /Length %d >> stream\n%s\nendstream endobj\n", len(stream), stream)
	xref := b.Len()
	write("xref\n0 6\n0000000000 65535 f \n")
	for _, offset := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&b, "trailer << /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

func splitFindings(findings []models.Finding) ([]models.Finding, []models.Finding) {
	var high []models.Finding
	var low []models.Finding
	for _, finding := range findings {
		switch finding.Severity {
		case models.SeverityCritical, models.SeverityHigh:
			high = append(high, finding)
		default:
			low = append(low, finding)
		}
	}
	return high, low
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
	default:
		return 1
	}
}

func findingIDs(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.ID)
	}
	return out
}

func cveIDs(cves []models.CVEMatch) []string {
	out := make([]string, 0, len(cves))
	for _, cve := range cves {
		out = append(out, cve.ID)
	}
	return out
}

func vectorIDs(vectors []models.AttackVector) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, vector.ID)
	}
	return out
}

func safeFilename(sessionID string, format models.ReportFormat) string {
	return fmt.Sprintf("nox-%s.%s", sessionID, format)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func pdfEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	return strings.ReplaceAll(value, ")", "\\)")
}
