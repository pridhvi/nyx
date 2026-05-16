package nox

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pridhvi/nox/internal/api"
	"github.com/pridhvi/nox/internal/config"
)

const version = "0.1.0-dev"

func Execute() {
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
	case "plugins":
		err = runPlugins(os.Args[2:])
	case "version":
		fmt.Println("nox", version)
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

func printUsage() {
	fmt.Fprintln(os.Stderr, `Nox - local web application penetration testing framework

Authorized use only: run Nox only against systems you own or have explicit,
written permission to test. Unauthorized scanning or exploitation may be illegal.

Usage:
  nox scan --target <host-or-url> [--mode passive|active|stealth]
  nox scan --source <repo-path>
  nox audit <repo-path> [--format terminal|json|sarif|html|md]
  nox serve [--host 127.0.0.1] [--port 6767]
  nox sessions list
  nox sessions show <id>
  nox sessions delete <id>
  nox sessions findings <id>
  nox sessions runs <id>
  nox sessions export <id> --output session.zip
  nox plugins list
  nox plugins install --name custom --phase vuln_scan <path>
  nox report <session-id> --format html|pdf|md --output report.html
  nox llm chat <session-id>
  nox llm analyse <session-id>
  nox config init
  nox config show
  nox version`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	host := fs.String("host", "127.0.0.1", "server host")
	port := fs.Int("port", 6767, "server port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
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
