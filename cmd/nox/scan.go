package nox

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/kanini/nox/internal/config"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	target := fs.String("target", "", "target host, URL, or CIDR")
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}
	selectedMode := firstNonEmpty(*mode, cfg.Scan.Mode, string(models.ScanModeActive))
	selectedLLMURL := firstNonEmpty(*llmURL, cfg.LLM.BaseURL)
	selectedLLMModel := firstNonEmpty(*llmModel, cfg.LLM.Model)
	if *noLLM || !cfg.LLM.Enabled {
		selectedLLMURL = ""
		selectedLLMModel = ""
	}
	selectedPhases := splitCSV(firstNonEmpty(*phases, strings.Join(cfg.Scan.Phases, ",")))
	_ = splitCSV(firstNonEmpty(*tools, strings.Join(cfg.Scan.Tools, ",")))
	_ = firstNonEmpty(*rateLimit, cfg.Scan.RateLimit)

	session, initialTarget, err := engine.NewPendingSession(engine.NewSessionInput{
		Target:        *target,
		Name:          *name,
		Mode:          models.ScanMode(selectedMode),
		OutOfScope:    splitCSV(*outOfScope),
		EnabledPhases: selectedPhases,
		LLMModel:      selectedLLMModel,
		LLMBaseURL:    selectedLLMURL,
	})
	if err != nil {
		return err
	}
	sessionDir := firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir())
	record, err := db.CreateSessionDB(context.Background(), sessionDir, session, initialTarget)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), sessionDir, record.Session.ID)
	if err != nil {
		return err
	}
	defer store.Close()
	runner := engine.NewRunner(store)
	if *concurrency > 0 {
		runner = engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), nil, engine.RunnerOptions{GlobalConcurrency: *concurrency, PerToolConcurrency: 1})
	}
	scanErr := runner.Run(context.Background(), record.Session)

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
