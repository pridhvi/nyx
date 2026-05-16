package nox

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/pridhvi/nox/internal/config"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/engine"
	llmintel "github.com/pridhvi/nox/internal/llm"
	"github.com/pridhvi/nox/internal/models"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	target := fs.String("target", "", "target host, URL, or CIDR")
	sourcePath := fs.String("source", "", "source repository path for static or combined analysis")
	name := fs.String("name", "", "engagement name")
	mode := fs.String("mode", "", "scan mode: passive, active, stealth")
	outOfScope := fs.String("out-of-scope", "", "comma-separated hosts or CIDRs to exclude")
	phases := fs.String("phases", "", "comma-separated scan phases")
	tools := fs.String("tools", "", "comma-separated tool ids")
	llmModel := fs.String("llm-model", "", "LLM model for post-scan analysis")
	llmURL := fs.String("llm-url", "", "OpenAI-compatible LLM base URL")
	noLLM := fs.Bool("no-llm", false, "disable post-scan LLM analysis")
	concurrency := fs.Int("concurrency", 0, "global scan concurrency")
	rateLimit := fs.String("rate-limit", "", "rate limit label for config compatibility")
	lean := fs.Bool("lean", false, "delete raw tool run sidecar logs after normalization")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *target == "" && strings.TrimSpace(*sourcePath) == "" {
		return fmt.Errorf("--target or --source is required")
	}
	selectedMode := firstNonEmpty(*mode, cfg.Scan.Mode, string(models.ScanModeActive))
	selectedLLMURL := firstNonEmpty(*llmURL, cfg.LLM.BaseURL)
	selectedLLMModel := firstNonEmpty(*llmModel, cfg.LLM.Model)
	if *noLLM || !cfg.LLM.Enabled {
		selectedLLMURL = ""
		selectedLLMModel = ""
	}
	selectedPhases := splitCSV(firstNonEmpty(*phases, strings.Join(cfg.Scan.Phases, ",")))
	selectedTools := splitCSV(firstNonEmpty(*tools, strings.Join(cfg.Scan.Tools, ",")))
	selectedRateLimit := firstNonEmpty(*rateLimit, cfg.Scan.RateLimit)

	input := engine.NewSessionInput{
		Target:        *target,
		SourcePath:    *sourcePath,
		Name:          *name,
		Mode:          models.ScanMode(selectedMode),
		OutOfScope:    splitCSV(*outOfScope),
		EnabledPhases: selectedPhases,
		EnabledTools:  selectedTools,
		RunnerOptions: models.ScanRunnerOptions{Concurrency: *concurrency, PerToolConcurrency: 1, RateLimit: selectedRateLimit},
		LLMModel:      selectedLLMModel,
		LLMBaseURL:    selectedLLMURL,
	}
	var session models.Session
	var initialTargets []models.Target
	if *target == "" {
		session, err = engine.NewPendingSourceSession(input)
	} else {
		if strings.TrimSpace(*sourcePath) != "" {
			input.WorkloadMode = models.WorkloadModeCombined
		}
		session, initialTargets, err = engine.NewPendingSessionWithTargets(input)
	}
	if err != nil {
		return err
	}
	sessionDir := firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir())
	record, err := db.CreateSessionDBWithTargets(context.Background(), sessionDir, session, initialTargets)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), sessionDir, record.Session.ID)
	if err != nil {
		return err
	}
	defer store.Close()
	scanErr := runScanWorkload(context.Background(), store, record.Session, engine.RunnerOptions{GlobalConcurrency: *concurrency, PerToolConcurrency: 1, Lean: *lean}, llmintel.Config{
		Provider: "openai-compatible",
		BaseURL:  selectedLLMURL,
		APIKey:   cfg.LLM.APIKey,
		Model:    selectedLLMModel,
	})

	fmt.Printf("created session %s for %s (%s mode)\n", record.Session.ID, record.Session.TargetInput, record.Session.Mode)
	fmt.Printf("db: %s\n", record.DBPath)
	if scanErr != nil {
		fmt.Println("status: failed")
		return scanErr
	}
	updated, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("status: %s; targets=%d findings=%d\n", updated.Status, updated.TargetCount, updated.FindingCount)
	return nil
}

func runScanWorkload(ctx context.Context, store *db.Store, session models.Session, options engine.RunnerOptions, llmConfig llmintel.Config) error {
	switch session.WorkloadMode {
	case models.WorkloadModeStatic:
		audit := engine.NewAuditRunner(store, engine.AuditOptions{Tools: auditToolIDs(session.EnabledTools), LLMConfig: llmConfig})
		return audit.Run(ctx, session, session.SourcePath)
	case models.WorkloadModeCombined:
		audit := engine.NewAuditRunner(store, engine.AuditOptions{Tools: auditToolIDs(session.EnabledTools), LLMConfig: llmConfig, KeepSessionOpen: true})
		if err := audit.Run(ctx, session, session.SourcePath); err != nil {
			return err
		}
		dynamicSession := session
		dynamicSession.EnabledTools = dynamicToolIDs(session.EnabledTools)
		runner := engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), nil, options)
		return runner.Run(ctx, dynamicSession)
	default:
		runner := engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), nil, options)
		return runner.Run(ctx, session)
	}
}

func auditToolIDs(tools []string) []string {
	var out []string
	for _, tool := range tools {
		if strings.HasPrefix(strings.TrimSpace(tool), "audit/") {
			out = append(out, tool)
		}
	}
	return out
}

func dynamicToolIDs(tools []string) []string {
	var out []string
	for _, tool := range tools {
		if !strings.HasPrefix(strings.TrimSpace(tool), "audit/") {
			out = append(out, tool)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
