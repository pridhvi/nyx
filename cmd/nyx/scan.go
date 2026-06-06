package nyx

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/engine"
	"github.com/pridhvi/nyx/internal/evasion"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
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
	evasionProfile := fs.String("evasion-profile", "", "request behavior profile: safe, normal, stealth, custom")
	proxyURL := fs.String("proxy", "", "proxy URL for compatible requests")
	userAgentProfile := fs.String("user-agent-profile", "", "user-agent profile")
	headerProfile := fs.String("header-profile", "", "header profile")
	jitterMS := fs.Int("jitter-ms", 0, "request jitter in milliseconds")
	adaptiveBackoff := fs.Bool("adaptive-backoff", false, "enable adaptive backoff on block signals")
	routeSeeds := fs.String("route-seeds", "", "comma-separated or newline-separated seed routes for authenticated/deep scans")
	routeSeedFile := fs.String("route-seed-file", "", "file containing seed routes, one per line")
	authHeader := fs.String("auth-header", "", "authentication header in 'Name: value' form")
	authCookie := fs.String("auth-cookie", "", "cookie header value or semicolon-separated name=value pairs")
	authProfilePath := fs.String("auth-profile", "", "JSON file describing a generic form or JSON login auth profile")
	secondaryAuthHeader := fs.String("secondary-auth-header", "", "secondary identity authentication header in 'Name: value' form for authorization checks")
	secondaryAuthCookie := fs.String("secondary-auth-cookie", "", "secondary identity cookie header for authorization checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *target == "" && strings.TrimSpace(*sourcePath) == "" {
		return fmt.Errorf("--target or --source is required")
	}
	selectedMode := firstNonEmpty(*mode, cfg.Scan.Mode, string(models.ScanModeActive))
	selectedLLMURL, selectedLLMModel, _ := selectLLMSettings(*noLLM, cfg.LLM.Enabled, *llmURL, *llmModel, cfg.LLM.BaseURL, cfg.LLM.Model)
	if strings.TrimSpace(selectedLLMURL) != "" {
		if err := llmintel.ValidateBaseURL(selectedLLMURL, llmintel.AllowedHostsFromEnv()); err != nil {
			return err
		}
	}
	selectedPhases := splitCSV(firstNonEmpty(*phases, strings.Join(cfg.Scan.Phases, ",")))
	selectedTools := splitCSV(firstNonEmpty(*tools, strings.Join(cfg.Scan.Tools, ",")))
	selectedRateLimit := firstNonEmpty(*rateLimit, cfg.Scan.RateLimit)

	runnerOptions, _, err := evasion.Normalize(models.ScanRunnerOptions{
		Concurrency:        *concurrency,
		PerToolConcurrency: 1,
		RateLimit:          selectedRateLimit,
		EvasionProfile:     *evasionProfile,
		ProxyURL:           *proxyURL,
		UserAgentProfile:   *userAgentProfile,
		HeaderProfile:      *headerProfile,
		JitterMS:           *jitterMS,
		AdaptiveBackoff:    *adaptiveBackoff,
	})
	if err != nil {
		return err
	}
	authProfile, err := readAuthProfileFile(*authProfilePath)
	if err != nil {
		return err
	}
	input := engine.NewSessionInput{
		Target:         *target,
		SourcePath:     *sourcePath,
		Name:           *name,
		Mode:           models.ScanMode(selectedMode),
		OutOfScope:     splitCSV(*outOfScope),
		EnabledPhases:  selectedPhases,
		EnabledTools:   selectedTools,
		ToolParameters: models.BuildScanToolParameters(nil, splitRouteSeeds(*routeSeeds), *routeSeedFile, parseHeaderMap(*authHeader), parseCookieMap(*authCookie), *authCookie, authProfile, parseHeaderMap(*secondaryAuthHeader), parseCookieMap(*secondaryAuthCookie), *secondaryAuthCookie),
		RunnerOptions:  runnerOptions,
		LLMModel:       selectedLLMModel,
		LLMBaseURL:     selectedLLMURL,
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
	engineOptions := engine.RunnerOptions{
		GlobalConcurrency:  runnerOptions.Concurrency,
		PerToolConcurrency: runnerOptions.PerToolConcurrency,
		Lean:               *lean,
		ProxyURL:           runnerOptions.ProxyURL,
		LLMConfig: llmintel.Config{
			Provider:     "openai-compatible",
			BaseURL:      selectedLLMURL,
			APIKey:       cfg.LLM.APIKey,
			Model:        selectedLLMModel,
			MaxTokens:    cfg.LLM.MaxTokens,
			Temperature:  cfg.LLM.Temperature,
			AllowedHosts: llmintel.AllowedHostsFromEnv(),
		},
	}
	scanErr := runScanWorkload(context.Background(), store, record.Session, engineOptions, engineOptions.LLMConfig)

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
		options.LLMConfig = llmConfig
		runner := engine.NewRunnerWithOptions(store, engine.DefaultSafeAdapters(), nil, options)
		return runner.Run(ctx, dynamicSession)
	default:
		options.LLMConfig = llmConfig
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

func splitRouteSeeds(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseHeaderMap(value string) map[string]string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	name := strings.TrimSpace(parts[0])
	headerValue := strings.TrimSpace(parts[1])
	if name == "" || headerValue == "" {
		return nil
	}
	return map[string]string{name: headerValue}
}

func parseCookieMap(value string) map[string]string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		pieces := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pieces) != 2 {
			continue
		}
		name := strings.TrimSpace(pieces[0])
		cookieValue := strings.TrimSpace(pieces[1])
		if name != "" && cookieValue != "" {
			out[name] = cookieValue
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readAuthProfileFile(path string) (map[string]any, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	body, err := os.ReadFile(path) // #nosec G304 -- auth profile path is an explicit operator-selected local input file.
	if err != nil {
		return nil, err
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("invalid auth profile JSON: %w", err)
	}
	return profile, nil
}
