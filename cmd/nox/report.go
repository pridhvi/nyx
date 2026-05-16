package nox

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pridhvi/nox/internal/config"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
	reportgen "github.com/pridhvi/nox/internal/report"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	format := fs.String("format", string(models.ReportFormatHTML), "report format: html, pdf, md, sarif")
	output := fs.String("output", "", "output path; stdout when empty")
	mode := fs.String("mode", string(models.ReportModeTechnical), "report mode: executive or technical")
	sessionID, flagArgs := splitLeadingSessionID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if sessionID == "" && fs.NArg() > 0 {
		sessionID = fs.Arg(0)
	}
	if sessionID == "" {
		return fmt.Errorf("report requires a session id")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	artifact, err := reportgen.Generate(context.Background(), store, reportgen.Options{
		Format: models.ReportFormat(*format),
		Mode:   models.ReportMode(*mode),
	})
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = os.Stdout.Write(artifact.Content)
		return err
	}
	if err := os.WriteFile(*output, artifact.Content, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *output)
	return nil
}

func splitLeadingSessionID(args []string) (string, []string) {
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		return args[0], args[1:]
	}
	return "", args
}
