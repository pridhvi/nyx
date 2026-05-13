package nox

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kanini/nox/internal/api"
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
	case "serve":
		err = runServe(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
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
  nox serve [--host 127.0.0.1] [--port 8080]
  nox sessions list
  nox sessions show <id>
  nox sessions delete <id>
  nox sessions findings <id>
  nox sessions runs <id>
  nox plugins list
  nox report <session-id>
  nox version`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "server host")
	port := fs.Int("port", 8080, "server port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	srv := api.NewServer(api.Config{Host: *host, Port: *port})
	return srv.ListenAndServe(context.Background())
}
