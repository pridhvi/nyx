package report

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
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
	ListSourceFindings(ctx context.Context, sessionID string, filter db.SourceFindingFilter) ([]models.SourceFinding, error)
	ListAttackGraphEdges(ctx context.Context, sessionID string) ([]models.AttackGraphEdge, error)
	ListPayloadsBySession(ctx context.Context, sessionID string, filter db.PayloadFilter) ([]models.Payload, error)
	ListCredentialFindings(ctx context.Context, sessionID string, filter db.CredentialFilter) ([]models.CredentialFinding, error)
	ListOSINTFindings(ctx context.Context, sessionID string, filter db.OSINTFilter) ([]models.OSINTFinding, error)
	ListADEntities(ctx context.Context, sessionID, entityType string) ([]models.ADEntity, error)
	ListADRelationships(ctx context.Context, sessionID string) ([]models.ADRelationship, error)
	ListPoCResults(ctx context.Context, sessionID, findingID string) ([]models.PoCResult, error)
	ListBlockEvents(ctx context.Context, sessionID string) ([]models.BlockEvent, error)
	ListProviderStatuses(ctx context.Context, sessionID string, filter db.ProviderStatusFilter) ([]models.ProviderStatus, error)
	ListPowerCallbacks(ctx context.Context, sessionID string, filter db.PowerCallbackFilter) ([]models.PowerCallback, error)
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
	sourceFindings, err := store.ListSourceFindings(ctx, session.ID, db.SourceFindingFilter{})
	if err != nil {
		return Artifact{}, err
	}
	graphEdges, err := store.ListAttackGraphEdges(ctx, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	power, err := collectPowerEvidence(ctx, store, session.ID)
	if err != nil {
		return Artifact{}, err
	}
	sections := buildSections(session, targets, findings, sourceFindings, graphEdges, cves, vectors, runs, analyses, stats, options.Mode, power)
	summary := sections[0].Content
	if options.Format == models.ReportFormatSARIF {
		if body, err := json.Marshal(activeFindings(findings)); err == nil {
			summary = string(body)
		}
	}
	report := models.Report{
		ID:              models.NewID(),
		SessionID:       session.ID,
		Title:           fmt.Sprintf("Nyx report for %s", session.TargetInput),
		Format:          options.Format,
		Mode:            options.Mode,
		Summary:         summary,
		Sections:        sections,
		FindingIDs:      findingIDs(findings),
		CVEMatchIDs:     cveIDs(cves),
		AttackVectorIDs: vectorIDs(vectors),
		GeneratedBy:     "nyx",
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

type powerEvidence struct {
	Payloads    []models.Payload
	Credentials []models.CredentialFinding
	OSINT       []models.OSINTFinding
	ADEntities  []models.ADEntity
	ADRelations []models.ADRelationship
	PoCs        []models.PoCResult
	Blocks      []models.BlockEvent
	Providers   []models.ProviderStatus
	Callbacks   []models.PowerCallback
}

func collectPowerEvidence(ctx context.Context, store Store, sessionID string) (powerEvidence, error) {
	var out powerEvidence
	var err error
	if out.Payloads, err = store.ListPayloadsBySession(ctx, sessionID, db.PayloadFilter{}); err != nil {
		return out, err
	}
	if out.Credentials, err = store.ListCredentialFindings(ctx, sessionID, db.CredentialFilter{}); err != nil {
		return out, err
	}
	if out.OSINT, err = store.ListOSINTFindings(ctx, sessionID, db.OSINTFilter{}); err != nil {
		return out, err
	}
	if out.ADEntities, err = store.ListADEntities(ctx, sessionID, ""); err != nil {
		return out, err
	}
	if out.ADRelations, err = store.ListADRelationships(ctx, sessionID); err != nil {
		return out, err
	}
	if out.PoCs, err = store.ListPoCResults(ctx, sessionID, ""); err != nil {
		return out, err
	}
	if out.Blocks, err = store.ListBlockEvents(ctx, sessionID); err != nil {
		return out, err
	}
	if out.Providers, err = store.ListProviderStatuses(ctx, sessionID, db.ProviderStatusFilter{}); err != nil {
		return out, err
	}
	if out.Callbacks, err = store.ListPowerCallbacks(ctx, sessionID, db.PowerCallbackFilter{}); err != nil {
		return out, err
	}
	return out, nil
}

func buildSections(session models.Session, targets []models.Target, findings []models.Finding, sourceFindings []models.SourceFinding, graphEdges []models.AttackGraphEdge, cves []models.CVEMatch, vectors []models.AttackVector, runs []models.ToolRun, analyses []models.LLMAnalysis, stats db.SessionStats, mode models.ReportMode, power powerEvidence) []models.ReportSection {
	active := activeFindings(findings)
	highs, lows := splitFindings(active)
	sections := []models.ReportSection{
		{ID: models.ReportSectionExecutiveSummary, Title: "Executive Summary", Content: executiveSummary(session, active, vectors, analyses, stats), Position: 1},
		{ID: models.ReportSectionScopeMethodology, Title: "Scope and Methodology", Content: scopeMethodology(session, targets, runs), Position: 2},
		{ID: models.ReportSectionSourceFindings, Title: "Static Source Findings", Content: sourceFindingsMarkdown(sourceFindings), Position: 3},
		{ID: models.ReportSectionHighFindings, Title: "Critical and High Findings", Content: findingsMarkdown(highs, true), Position: 4},
		{ID: models.ReportSectionLowerFindings, Title: "Medium, Low, and Informational Findings", Content: findingsMarkdown(lows, mode == models.ReportModeTechnical), Position: 5},
		{ID: models.ReportSectionCrossConfirmed, Title: "Cross-Confirmed Findings", Content: crossConfirmedMarkdown(findings, sourceFindings, graphEdges), Position: 6},
		{ID: models.ReportSectionAttackVectors, Title: "Attack Vectors", Content: vectorsMarkdown(vectors), Position: 7},
		{ID: models.ReportSectionCVEMatches, Title: "Dependency and CVE Matches", Content: cvesMarkdown(cves), Position: 8},
		{ID: models.ReportSectionPowerFeatures, Title: "Power Feature Evidence", Content: powerEvidenceMarkdown(power), Position: 9},
		{ID: models.ReportSectionToolCoverage, Title: "Tool Coverage", Content: toolCoverageMarkdown(runs), Position: 10},
		{ID: models.ReportSectionSuppressed, Title: "Suppressed and Dismissed Findings", Content: suppressedFindingsMarkdown(findings), Position: 11},
		{ID: models.ReportSectionRemediation, Title: "Remediation Roadmap", Content: remediationMarkdown(active, cves), Position: 12},
	}
	if mode == models.ReportModeTechnical {
		sections = append(sections, models.ReportSection{ID: models.ReportSectionRawEvidence, Title: "Raw Tool Output Appendix", Content: rawEvidenceMarkdown(active, runs), Position: 13})
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
	return fmt.Sprintf("The %s scan of %s produced %d findings across %d targets. Severity counts: critical=%d, high=%d, medium=%d, low=%d, info=%d. Nyx generated %d deterministic attack vectors from persisted evidence.",
		session.Mode, session.TargetInput, stats.FindingCount, stats.TargetCount,
		stats.SeverityCounts[string(models.SeverityCritical)], stats.SeverityCounts[string(models.SeverityHigh)], stats.SeverityCounts[string(models.SeverityMedium)], stats.SeverityCounts[string(models.SeverityLow)], stats.SeverityCounts[string(models.SeverityInfo)], len(vectors))
}

func scopeMethodology(session models.Session, targets []models.Target, runs []models.ToolRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- Target input: %s\n- Source path: %s\n- Mode: %s\n- Workload mode: %s\n- In scope: %s\n- Out of scope: %s\n\n", firstNonEmpty(session.TargetInput, "(none)"), firstNonEmpty(session.SourcePath, "(none)"), session.Mode, session.WorkloadMode, strings.Join(session.InScope, ", "), strings.Join(session.OutOfScope, ", "))
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
		pkg := strings.TrimSpace(cve.PackageName)
		if cve.PackageVersion != "" {
			pkg += "@" + cve.PackageVersion
		}
		if pkg != "" {
			pkg = " package=" + pkg
		}
		fmt.Fprintf(&b, "- **%s** CVSS %.1f patch=%t exploit=%t source=%s%s\n  %s\n", cve.CVEID, cve.CVSSv3Score, cve.PatchAvailable, cve.ExploitAvailable, cve.Source, pkg, cve.Description)
	}
	return strings.TrimSpace(b.String())
}

func sourceFindingsMarkdown(findings []models.SourceFinding) string {
	if len(findings) == 0 {
		return "No static source findings were recorded."
	}
	var b strings.Builder
	for _, finding := range findings {
		state := "static"
		if finding.ConfirmedByDynamic {
			state = "static + dynamic"
		}
		fmt.Fprintf(&b, "- **%s** %s:%d `%s` [%s]\n", finding.Kind, finding.FilePath, finding.LineNumber, finding.Value, state)
	}
	return strings.TrimSpace(b.String())
}

func powerEvidenceMarkdown(power powerEvidence) string {
	if len(power.Payloads) == 0 && len(power.Credentials) == 0 && len(power.OSINT) == 0 && len(power.ADEntities) == 0 && len(power.PoCs) == 0 && len(power.Blocks) == 0 && len(power.Providers) == 0 && len(power.Callbacks) == 0 {
		return "No power-feature evidence was recorded."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Power evidence summary: payloads=%d, credentials=%d, osint=%d, ad_entities=%d, ad_relationships=%d, poc_results=%d, callbacks=%d, block_events=%d, provider_statuses=%d.\n\n",
		len(power.Payloads), len(power.Credentials), len(power.OSINT), len(power.ADEntities), len(power.ADRelations), len(power.PoCs), len(power.Callbacks), len(power.Blocks), len(power.Providers))
	if len(power.Providers) > 0 {
		writePowerSubsection(&b, "Provider statuses", len(power.Providers))
		for _, status := range power.Providers {
			fmt.Fprintf(&b, "- `%s/%s` **%s**: %s\n", status.Provider, status.Module, status.Status, firstNonEmpty(status.Message, "(no message)"))
		}
		b.WriteString("\n")
	}
	if len(power.Payloads) > 0 {
		writePowerSubsection(&b, "Generated and validated payloads", len(power.Payloads))
		for _, payload := range power.Payloads {
			state := "unvalidated"
			if payload.Validated {
				state = "validated"
			}
			fmt.Fprintf(&b, "- `%s` **%s** confidence=%.2f bypass=%s context=%s\n", payload.PayloadType, state, payload.Confidence, firstNonEmpty(payload.BypassTechnique, "none"), truncate(payload.Context, 180))
		}
		b.WriteString("\n")
	}
	if len(power.Credentials) > 0 {
		writePowerSubsection(&b, "Credential checks", len(power.Credentials))
		for _, credential := range power.Credentials {
			status := "unconfirmed"
			if credential.Valid {
				status = "valid"
			}
			if credential.LockoutDetected {
				status = "lockout_detected"
			}
			fmt.Fprintf(&b, "- `%s` user=%s service=%s status=**%s** password=%s evidence=%s\n", credential.CredentialType, credential.Username, credential.Service, status, redactReportSecret(credential.Password), truncate(credential.Evidence, 180))
		}
		b.WriteString("\n")
	}
	if len(power.OSINT) > 0 {
		writePowerSubsection(&b, "OSINT findings", len(power.OSINT))
		for _, finding := range power.OSINT {
			fmt.Fprintf(&b, "- %s %s source=%s confidence=%.2f\n", finding.Kind, finding.Value, finding.Source, finding.Confidence)
		}
		b.WriteString("\n")
	}
	if len(power.ADEntities) > 0 {
		writePowerSubsection(&b, "AD/Internal records", len(power.ADEntities))
		for _, entity := range power.ADEntities {
			fmt.Fprintf(&b, "- %s %s domain=%s\n", entity.EntityType, entity.Name, entity.Domain)
		}
		if len(power.ADRelations) > 0 {
			fmt.Fprintf(&b, "- relationship records: %d\n", len(power.ADRelations))
		}
		b.WriteString("\n")
	}
	if len(power.PoCs) > 0 {
		writePowerSubsection(&b, "PoC impact records", len(power.PoCs))
		for _, result := range power.PoCs {
			fmt.Fprintf(&b, "- %s status=%s callback=%t evidence=%s\n", result.PoCType, result.Status, result.CallbackReceived, truncate(result.Evidence, 220))
		}
		b.WriteString("\n")
	}
	if len(power.Callbacks) > 0 {
		writePowerSubsection(&b, "Callback evidence", len(power.Callbacks))
		for _, callback := range power.Callbacks {
			fmt.Fprintf(&b, "- provider=%s token=%s received=%t source_ip=%s\n", callback.Provider, callback.Token, callback.Received, callback.SourceIP)
		}
		b.WriteString("\n")
	}
	if len(power.Blocks) > 0 {
		writePowerSubsection(&b, "Block and backoff events", len(power.Blocks))
		for _, event := range power.Blocks {
			fmt.Fprintf(&b, "- %s status=%d signal=%s backoff_ms=%d\n", event.ToolID, event.StatusCode, event.Signal, event.BackoffMS)
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

func writePowerSubsection(b *strings.Builder, title string, count int) {
	fmt.Fprintf(b, "### %s (%d)\n", title, count)
}

func redactReportSecret(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(empty)"
	}
	if value == "********" {
		return value
	}
	return "********"
}

func crossConfirmedMarkdown(findings []models.Finding, sourceFindings []models.SourceFinding, edges []models.AttackGraphEdge) string {
	if len(edges) == 0 {
		return "No static and dynamic confirmations were generated."
	}
	findingByID := map[string]models.Finding{}
	sourceByID := map[string]models.SourceFinding{}
	for _, finding := range findings {
		findingByID["finding:"+finding.ID] = finding
	}
	for _, finding := range sourceFindings {
		sourceByID["source:"+finding.ID] = finding
	}
	var b strings.Builder
	for _, edge := range edges {
		if edge.Relation != models.RelationConfirms {
			continue
		}
		source, sourceOK := sourceByID[edge.FromID]
		finding, findingOK := findingByID[edge.ToID]
		if sourceOK && findingOK {
			fmt.Fprintf(&b, "- %s:%d `%s` confirms **%s** (confidence %.2f)\n", source.FilePath, source.LineNumber, source.Value, finding.Title, edge.Confidence)
		}
	}
	if strings.TrimSpace(b.String()) == "" {
		return "No static and dynamic confirmations were generated."
	}
	return strings.TrimSpace(b.String())
}

func toolCoverageMarkdown(runs []models.ToolRun) string {
	if len(runs) == 0 {
		return "No tool runs were recorded."
	}
	var b strings.Builder
	for _, run := range runs {
		logState := "logs unavailable"
		if run.StdoutPath != "" || run.StderrPath != "" {
			logState = "logs retained"
		}
		fmt.Fprintf(&b, "- %s exit=%d findings=%d duration_ms=%d %s\n", run.ToolID, run.ExitCode, run.FindingCount, run.DurationMS, logState)
	}
	return strings.TrimSpace(b.String())
}

func suppressedFindingsMarkdown(findings []models.Finding) string {
	var b strings.Builder
	for _, finding := range findings {
		if finding.Status == models.FindingStatusSuppressed || finding.Status == models.FindingStatusFalsePositive {
			fmt.Fprintf(&b, "- **%s** [%s] %s (%s)\n", finding.Title, finding.Status, finding.URL, finding.ToolID)
		}
	}
	if strings.TrimSpace(b.String()) == "" {
		return "No suppressed or false-positive findings were recorded."
	}
	return strings.TrimSpace(b.String())
}

func activeFindings(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Status == models.FindingStatusSuppressed || finding.Status == models.FindingStatusFalsePositive {
			continue
		}
		out = append(out, finding)
	}
	return out
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

func rawEvidenceMarkdown(findings []models.Finding, _ []models.ToolRun) string {
	var b strings.Builder
	for _, finding := range findings {
		fmt.Fprintf(&b, "### %s\n\nRaw evidence:\n\n```text\n%s\n```\n\n", finding.Title, truncate(finding.EvidenceRaw, 2000))
		if finding.HTTPEvidence != nil {
			fmt.Fprintf(&b, "HTTP request:\n\n```text\n%s\n```\n\nHTTP response:\n\n```text\n%s\n```\n\n", truncate(finding.HTTPEvidence.RequestRaw, 2000), truncate(finding.HTTPEvidence.ResponseRaw, 2000))
		}
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
	case models.ReportFormatSARIF:
		return renderSARIF(report), "application/sarif+json"
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
	pdf := fpdf.New("P", "mm", "Letter", "")
	pdf.SetTitle("Nyx Security Report", false)
	pdf.SetAuthor("nyx", false)
	pdf.SetMargins(18, 16, 18)
	pdf.SetAutoPageBreak(true, 18)
	pdf.AddPage()
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " ")
		switch {
		case strings.HasPrefix(line, "# "):
			pdf.SetFont("Helvetica", "B", 18)
			pdf.MultiCell(0, 9, strings.TrimPrefix(line, "# "), "", "L", false)
			pdf.Ln(2)
		case strings.HasPrefix(line, "## "):
			pdf.Ln(2)
			pdf.SetFont("Helvetica", "B", 13)
			pdf.MultiCell(0, 7, strings.TrimPrefix(line, "## "), "", "L", false)
			pdf.Ln(1)
		case strings.HasPrefix(line, "### "):
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 11)
			pdf.MultiCell(0, 6, strings.TrimPrefix(line, "### "), "", "L", false)
		case strings.TrimSpace(line) == "":
			pdf.Ln(2)
		case strings.HasPrefix(line, "```"):
			continue
		default:
			pdf.SetFont("Helvetica", "", 9.5)
			pdf.MultiCell(0, 5.2, stripMarkdown(line), "", "L", false)
		}
	}
	var out strings.Builder
	if err := pdf.Output(&out); err != nil {
		return []byte("%PDF-1.4\n% report generation failed\n")
	}
	return []byte(out.String())
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
	return fmt.Sprintf("nyx-%s.%s", sessionID, format)
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

func stripMarkdown(value string) string {
	value = strings.ReplaceAll(value, "**", "")
	value = strings.ReplaceAll(value, "`", "")
	return value
}
