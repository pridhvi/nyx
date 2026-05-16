package nox

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pridhvi/nox/internal/adapters"
	"github.com/pridhvi/nox/internal/config"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/engine"
	llmintel "github.com/pridhvi/nox/internal/llm"
	"github.com/pridhvi/nox/internal/models"
	reportgen "github.com/pridhvi/nox/internal/report"
)

func runAudit(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "tools":
			return auditToolsCommand()
		case "findings":
			return auditFindingsCommand(args[1:])
		case "report":
			return auditReportCommand(args[1:])
		}
	}
	return auditRunCommand(args)
}

func auditRunCommand(args []string) error {
	sourcePath, flagArgs := splitLeadingSessionID(args)
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	name := fs.String("name", "", "audit session name")
	format := fs.String("format", "terminal", "output format: terminal, json, sarif, html, md")
	output := fs.String("output", "", "output path; stdout when empty")
	failOn := fs.String("fail-on", "", "exit non-zero when findings meet severity: critical, high, medium, low")
	diff := fs.String("diff", "", "comma-separated repository paths to include")
	tools := fs.String("tools", "", "comma-separated audit tool ids")
	llmModel := fs.String("llm-model", "", "LLM model for audit review")
	llmURL := fs.String("llm-url", "", "OpenAI-compatible LLM base URL")
	noLLM := fs.Bool("no-llm", false, "disable audit LLM review")
	offline := fs.Bool("offline", false, "avoid audit tools that require network access")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if sourcePath == "" && fs.NArg() > 0 {
		sourcePath = fs.Arg(0)
	}
	if strings.TrimSpace(sourcePath) == "" {
		return fmt.Errorf("audit requires a source path")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	selectedLLMURL := firstNonEmpty(*llmURL, cfg.LLM.BaseURL)
	selectedLLMModel := firstNonEmpty(*llmModel, cfg.LLM.Model)
	if *noLLM || !cfg.LLM.Enabled {
		selectedLLMURL = ""
		selectedLLMModel = ""
	}
	session, err := engine.NewPendingSourceSession(engine.NewSessionInput{
		SourcePath:    sourcePath,
		Name:          *name,
		EnabledTools:  normaliseAuditTools(splitCSV(*tools)),
		RunnerOptions: models.ScanRunnerOptions{PerToolConcurrency: 1},
		LLMModel:      selectedLLMModel,
		LLMBaseURL:    selectedLLMURL,
	})
	if err != nil {
		return err
	}
	sessionDir := firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir())
	record, err := db.CreateSessionDBWithTargets(context.Background(), sessionDir, session, nil)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), sessionDir, record.Session.ID)
	if err != nil {
		return err
	}
	defer store.Close()
	runner := engine.NewAuditRunner(store, engine.AuditOptions{
		Tools:     session.EnabledTools,
		DiffPaths: splitCSV(*diff),
		NoLLM:     *noLLM || !cfg.LLM.Enabled,
		Offline:   *offline,
		LLMConfig: llmintel.Config{
			Provider: "openai-compatible",
			BaseURL:  selectedLLMURL,
			APIKey:   cfg.LLM.APIKey,
			Model:    selectedLLMModel,
		},
	})
	runErr := runner.Run(context.Background(), record.Session, sourcePath)
	findings, listErr := store.ListFindings(context.Background(), record.Session.ID, db.FindingFilter{})
	if listErr != nil {
		return listErr
	}
	if err := writeAuditOutput(context.Background(), store, record.Session.ID, models.ReportFormat(*format), *output, findings); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "created audit session %s\n", record.Session.ID)
	fmt.Fprintf(os.Stderr, "db: %s\n", record.DBPath)
	if runErr != nil {
		return runErr
	}
	if threshold := strings.TrimSpace(*failOn); threshold != "" && findingsMeetSeverity(findings, threshold) {
		return fmt.Errorf("audit findings meet --fail-on %s", threshold)
	}
	return nil
}

func auditToolsCommand() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tLANGUAGES\tAVAILABLE")
	for _, adapter := range adapters.AllStatic() {
		fmt.Fprintf(w, "audit/%s\t%s\t%s\t%t\n", adapter.ID(), adapter.Name(), strings.Join(adapter.Languages(), ","), adapter.Available())
	}
	return w.Flush()
}

func auditFindingsCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("audit findings requires a session id")
	}
	sessionDir, err := configuredSessionDir("")
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), sessionDir, args[0])
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	findings, err := store.ListFindings(context.Background(), session.ID, db.FindingFilter{})
	if err != nil {
		return err
	}
	return printFindings(findings)
}

func auditReportCommand(args []string) error {
	return runReport(args)
}

func writeAuditOutput(ctx context.Context, store *db.Store, sessionID string, format models.ReportFormat, output string, findings []models.Finding) error {
	switch format {
	case "", "terminal":
		return printFindings(findings)
	case "json":
		body, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			return err
		}
		return writeAuditBytes(output, append(body, '\n'))
	case models.ReportFormatHTML, models.ReportFormatMarkdown, models.ReportFormatPDF, models.ReportFormatSARIF:
		artifact, err := reportgen.Generate(ctx, store, reportgen.Options{Format: format, Mode: models.ReportModeTechnical})
		if err != nil {
			return err
		}
		return writeAuditBytes(output, artifact.Content)
	default:
		return fmt.Errorf("unsupported audit format %q", format)
	}
}

func writeAuditBytes(output string, body []byte) error {
	if strings.TrimSpace(output) == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	if err := os.WriteFile(output, body, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", output)
	return nil
}

func printFindings(findings []models.Finding) error {
	if len(findings) == 0 {
		fmt.Println("no findings found")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tSTATUS\tTOOL\tTITLE\tLOCATION")
	for _, finding := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", finding.Severity, firstNonEmpty(finding.Status, "confirmed"), finding.ToolID, finding.Title, finding.URL)
	}
	return w.Flush()
}

func normaliseAuditTools(tools []string) []string {
	var out []string
	for _, tool := range tools {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			continue
		}
		if !strings.HasPrefix(tool, "audit/") {
			tool = "audit/" + tool
		}
		out = append(out, tool)
	}
	return out
}

func findingsMeetSeverity(findings []models.Finding, threshold string) bool {
	minRank := severityRank(models.Severity(strings.ToLower(threshold)))
	if minRank == 0 {
		return false
	}
	for _, finding := range findings {
		if finding.Status == "suppressed" {
			continue
		}
		if severityRank(finding.Severity) >= minRank {
			return true
		}
	}
	return false
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
