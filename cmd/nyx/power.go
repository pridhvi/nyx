package nyx

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pridhvi/nyx/internal/activedirectory"
	"github.com/pridhvi/nyx/internal/burp"
	"github.com/pridhvi/nyx/internal/config"
	"github.com/pridhvi/nyx/internal/creds"
	"github.com/pridhvi/nyx/internal/db"
	llmintel "github.com/pridhvi/nyx/internal/llm"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/osint"
	"github.com/pridhvi/nyx/internal/payload"
	"github.com/pridhvi/nyx/internal/poc"
)

func runPayloads(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx payloads generate|validate|list <session-id>")
	}
	sessionID := args[1]
	cfg, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("payloads generate", flag.ContinueOnError)
		findingID := fs.String("finding", "", "finding id")
		force := fs.Bool("force", false, "force regeneration")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *findingID == "" {
			return fmt.Errorf("--finding is required")
		}
		payloads, err := payload.Generate(context.Background(), store, sessionID, *findingID, payload.GenerateOptions{Force: *force, LLMConfig: llmintel.ConfigFromApp(cfg)})
		if err != nil {
			return err
		}
		return printJSON(payloads)
	case "validate":
		fs := flag.NewFlagSet("payloads validate", flag.ContinueOnError)
		payloadID := fs.String("payload", "", "payload id")
		confirm := fs.Bool("confirm", false, "confirm safe active validation")
		enabled := fs.Bool("enabled", cfg.Power.ActiveValidation.Enabled, "enable safe active validation for this command")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *payloadID == "" {
			return fmt.Errorf("--payload is required")
		}
		session, err := store.GetSession(context.Background())
		if err != nil {
			return err
		}
		result, err := payload.Validate(context.Background(), store, session, *payloadID, payload.ValidationOptions{Confirm: *confirm, Enabled: *enabled})
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		payloads, err := store.ListPayloadsBySession(context.Background(), sessionID, db.PayloadFilter{})
		if err != nil {
			return err
		}
		return printJSON(payloads)
	default:
		return fmt.Errorf("usage: nyx payloads generate|validate|list <session-id>")
	}
}

func runCreds(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx creds test|list|redact <session-id>")
	}
	sessionID := args[1]
	cfg, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "test":
		fs := flag.NewFlagSet("creds test", flag.ContinueOnError)
		mode := fs.String("mode", "correlate", "defaults, spray, or correlate")
		username := fs.String("username", "", "username")
		password := fs.String("password", "", "password")
		service := fs.String("service", "web", "service label")
		url := fs.String("url", "", "fixture-safe login URL")
		confirm := fs.Bool("confirm", false, "confirm active credential checks")
		storeSecret := fs.Bool("store-secret", false, "store plaintext only when config also permits it")
		maxAttempts := fs.Int("max-attempts", cfg.Power.Credentials.MaxAttemptsPerUser, "maximum attempts per user")
		delayMS := fs.Int("delay-ms", int((time.Duration(cfg.Power.Credentials.DelaySeconds)*time.Second)/time.Millisecond), "delay between attempts in milliseconds")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		results, err := creds.Run(context.Background(), store, sessionID, creds.TestRequest{
			Mode:        *mode,
			Username:    *username,
			Password:    *password,
			Service:     *service,
			URL:         *url,
			Confirm:     *confirm,
			StoreSecret: *storeSecret && cfg.Power.Credentials.StorePlaintext,
			MaxAttempts: *maxAttempts,
			DelayMS:     *delayMS,
		})
		if err != nil {
			return err
		}
		return printJSON(creds.RedactAll(results, false))
	case "list":
		results, err := store.ListCredentialFindings(context.Background(), sessionID, db.CredentialFilter{})
		if err != nil {
			return err
		}
		return printJSON(creds.RedactAll(results, false))
	default:
		return fmt.Errorf("usage: nyx creds test|list <session-id>")
	}
}

func runOSINT(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx osint run|list <session-id>")
	}
	sessionID := args[1]
	cfg, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("osint run", flag.ContinueOnError)
		providers := fs.String("providers", "", "comma-separated provider names")
		confirmSeed := fs.Bool("confirm-seed", false, "allow in-scope discovered targets to be seeded")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		results, err := osint.RunWithConfig(context.Background(), store, session, osint.RunRequest{Providers: splitCSV(*providers), ConfirmSeed: *confirmSeed}, cfg.Power, http.DefaultClient)
		if err != nil {
			return err
		}
		return printJSON(results)
	case "list":
		results, err := store.ListOSINTFindings(context.Background(), sessionID, db.OSINTFilter{})
		if err != nil {
			return err
		}
		return printJSON(results)
	default:
		return fmt.Errorf("usage: nyx osint run|list <session-id>")
	}
}

func runAD(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx ad enum|kerberoast|bloodhound <session-id>")
	}
	if args[0] == "bloodhound" && len(args) >= 3 && args[1] == "export" {
		sessionID := args[2]
		store, err := openSessionStore("", sessionID)
		if err != nil {
			return err
		}
		defer store.Close()
		entities, _ := store.ListADEntities(context.Background(), sessionID, "")
		relationships, _ := store.ListADRelationships(context.Background(), sessionID)
		return printJSON(map[string]any{"entities": entities, "relationships": relationships})
	}
	sessionID := args[1]
	_, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	switch args[0] {
	case "enum":
		fs := flag.NewFlagSet("ad enum", flag.ContinueOnError)
		domain := fs.String("domain", "", "AD domain")
		allowPublic := fs.Bool("allow-public", false, "allow non-private scope")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		entities, err := activedirectory.RecordEnumRequest(context.Background(), store, session, *domain, *allowPublic)
		if err != nil {
			return err
		}
		relay, relayErr := activedirectory.RecordRelayRisks(context.Background(), store, session)
		if relayErr != nil {
			return relayErr
		}
		return printJSON(map[string]any{"entities": entities, "relay_risks": relay})
	case "kerberoast":
		fs := flag.NewFlagSet("ad kerberoast", flag.ContinueOnError)
		domain := fs.String("domain", "", "AD domain")
		username := fs.String("username", "", "username or SPN label")
		confirm := fs.Bool("confirm", false, "confirm request recording")
		allowPublic := fs.Bool("allow-public", false, "allow non-private scope")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		artifact, err := activedirectory.RecordKerberoastRequest(context.Background(), store, session, activedirectory.KerberoastRequest{Domain: *domain, Username: *username, Confirm: *confirm, AllowPublic: *allowPublic})
		if err != nil {
			return err
		}
		return printJSON(artifact)
	default:
		return fmt.Errorf("usage: nyx ad enum|kerberoast <session-id> or nyx ad bloodhound export <session-id>")
	}
}

func runPoC(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx poc run|list <session-id>")
	}
	sessionID := args[1]
	cfg, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("poc run", flag.ContinueOnError)
		findingID := fs.String("finding", "", "finding id")
		pocType := fs.String("type", "", "poc type override")
		payloadID := fs.String("payload", "", "payload id")
		confirm := fs.Bool("confirm", false, "confirm active PoC recording")
		active := fs.Bool("active", cfg.Power.ActiveValidation.Enabled, "enable safe active validation")
		callbackBase := fs.String("callback-base-url", "", "callback base URL")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *findingID == "" {
			return fmt.Errorf("--finding is required")
		}
		result, err := poc.Run(context.Background(), store, sessionID, *findingID, poc.RunRequest{Confirm: *confirm, PoCType: *pocType, PayloadID: *payloadID, ActiveValidationEnabled: *active, CallbackBaseURL: *callbackBase})
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		results, err := store.ListPoCResults(context.Background(), sessionID, "")
		if err != nil {
			return err
		}
		return printJSON(results)
	default:
		return fmt.Errorf("usage: nyx poc run|list <session-id>")
	}
}

func runBurp(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nyx burp status|push-scope|pull-issues <session-id> or nyx burp export scope|findings <session-id> --output file.xml")
	}
	if args[0] == "export" && len(args) >= 3 {
		return runBurpExport(args)
	}
	sessionID := args[1]
	cfg, store, err := openPowerSession("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("burp status", flag.ContinueOnError)
		baseURL := fs.String("base-url", cfg.Power.Burp.BaseURL, "Burp REST base URL")
		apiKey := fs.String("api-key", cfg.Power.Burp.APIKey, "Burp REST API key")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		result := burp.Status(context.Background(), burpConfig(*baseURL, *apiKey, cfg), http.DefaultClient)
		return printJSON(result)
	case "push-scope":
		fs := flag.NewFlagSet("burp push-scope", flag.ContinueOnError)
		baseURL := fs.String("base-url", cfg.Power.Burp.BaseURL, "Burp REST base URL")
		apiKey := fs.String("api-key", cfg.Power.Burp.APIKey, "Burp REST API key")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		result, err := burp.PushScope(context.Background(), store, sessionID, burpConfig(*baseURL, *apiKey, cfg), http.DefaultClient)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "pull-issues":
		fs := flag.NewFlagSet("burp pull-issues", flag.ContinueOnError)
		baseURL := fs.String("base-url", cfg.Power.Burp.BaseURL, "Burp REST base URL")
		apiKey := fs.String("api-key", cfg.Power.Burp.APIKey, "Burp REST API key")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		session, err := store.GetSession(context.Background())
		if err != nil {
			return err
		}
		imported, result, err := burp.PullIssues(context.Background(), store, session, burpConfig(*baseURL, *apiKey, cfg), http.DefaultClient)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"result": result, "imported": imported})
	default:
		return fmt.Errorf("usage: nyx burp status|push-scope|pull-issues <session-id> or nyx burp export scope|findings <session-id> --output file.xml")
	}
}

func runBurpExport(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: nyx burp export scope|findings <session-id> --output file.xml")
	}
	kind := args[1]
	sessionID := args[2]
	fs := flag.NewFlagSet("burp export", flag.ContinueOnError)
	output := fs.String("output", "", "output file")
	if err := fs.Parse(args[3:]); err != nil {
		return err
	}
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	var raw []byte
	switch kind {
	case "scope":
		raw, err = burp.ExportScope(context.Background(), store, sessionID)
	case "findings":
		raw, err = burp.ExportFindings(context.Background(), store, sessionID)
	default:
		return fmt.Errorf("usage: nyx burp export scope|findings <session-id>")
	}
	if err != nil {
		return err
	}
	if *output == "" {
		fmt.Println(string(raw))
		return nil
	}
	return os.WriteFile(*output, raw, 0o600) // #nosec G703 -- output path is an explicit operator-selected export destination.
}

func openPowerSession(configPath, sessionID string) (config.Config, *db.Store, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	store, err := db.OpenSession(context.Background(), firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), sessionID)
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, store, nil
}

func openSessionStore(configPath, sessionID string) (*db.Store, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return db.OpenSession(context.Background(), firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), sessionID)
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func burpConfig(baseURL, apiKey string, cfg config.Config) models.BurpConfig {
	now := time.Now().UTC()
	return models.BurpConfig{
		ID:                   "cli",
		BaseURL:              baseURL,
		APIKey:               apiKey,
		CollaboratorProvider: cfg.Power.Callbacks.Provider,
		CollaboratorURL:      cfg.Power.Callbacks.InteractshURL,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}
