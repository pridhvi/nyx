package nyx

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pridhvi/nyx/internal/api"
	"github.com/pridhvi/nyx/internal/config"
	nyxlog "github.com/pridhvi/nyx/internal/logging"
)

const version = "0.1.0-dev"

func Execute() {
	if err := nyxlog.ConfigureFromEnv(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "llm":
		err = runLLM(os.Args[2:])
	case "config":
		err = runConfig(os.Args[2:])
	case "sessions":
		err = runSessions(os.Args[2:])
	case "monitor":
		err = runMonitor(os.Args[2:])
	case "payloads":
		err = runPayloads(os.Args[2:])
	case "creds":
		err = runCreds(os.Args[2:])
	case "osint":
		err = runOSINT(os.Args[2:])
	case "ad":
		err = runAD(os.Args[2:])
	case "poc":
		err = runPoC(os.Args[2:])
	case "burp":
		err = runBurp(os.Args[2:])
	case "plugins":
		err = runPlugins(os.Args[2:])
	case "version":
		fmt.Println("nyx", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	if err := nyxlog.Configure(nyxlog.Options{Level: cfg.Logging.Level, Format: cfg.Logging.Format}); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Nyx - local web application penetration testing framework

Authorized use only: run Nyx only against systems you own or have explicit,
written permission to test. Unauthorized scanning or exploitation may be illegal.

Usage:
  nyx scan --target <host-or-url> [--mode passive|active|stealth]
  nyx scan --source <repo-path>
  nyx audit <repo-path> [--format terminal|json|sarif|html|md]
  nyx serve [--host 127.0.0.1] [--port 6767]
  nyx sessions list
  nyx sessions show <id>
  nyx sessions delete <id>
  nyx sessions findings <id>
  nyx sessions runs <id>
  nyx sessions export <id> --output session.zip
  nyx monitor create --target <host-or-url> --schedule '@daily'
  nyx monitor list
  nyx monitor run <config-id>
  nyx payloads list <session-id>
  nyx creds list <session-id>
  nyx osint list <session-id>
  nyx ad bloodhound export <session-id>
  nyx poc list <session-id>
  nyx burp export scope <session-id> --output scope.xml
  nyx plugins list
  nyx plugins install --name custom --phase vuln_scan <path>
  nyx report <session-id> --format html|pdf|md --output report.html
  nyx llm chat <session-id>
  nyx llm analyse <session-id>
  nyx config init
  nyx config show
  nyx payloads validate <session-id> --payload <id> --confirm --enabled=true
  nyx creds test <session-id> --mode defaults --url <login-url> --username <user> --password <pass> --confirm
  nyx osint run <session-id> --providers github,shodan,securitytrails
  nyx ad kerberoast <session-id> --username svc-http --confirm
  nyx burp status <session-id>
  nyx version`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	host := fs.String("host", "127.0.0.1", "server host")
	port := fs.Int("port", 6767, "server port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if fs.Lookup("host").Value.String() == "127.0.0.1" && cfg.Server.Host != "" {
		*host = cfg.Server.Host
	}
	if *port == 6767 && cfg.Server.Port != 0 {
		*port = cfg.Server.Port
	}
	srv := api.NewServer(api.Config{Host: *host, Port: *port, SessionDir: cfg.Database.SessionDir, APIKey: cfg.Server.APIKey, ToolPaths: cfg.Tools, AppConfig: cfg})
	return srv.ListenAndServe(context.Background())
}
