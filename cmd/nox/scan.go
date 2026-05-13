package nox

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	target := fs.String("target", "", "target host, URL, or CIDR")
	name := fs.String("name", "", "engagement name")
	mode := fs.String("mode", string(models.ScanModeActive), "scan mode: passive, active, stealth")
	outOfScope := fs.String("out-of-scope", "", "comma-separated hosts or CIDRs to exclude")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}

	session, initialTarget, err := engine.NewPendingSession(engine.NewSessionInput{
		Target:     *target,
		Name:       *name,
		Mode:       models.ScanMode(*mode),
		OutOfScope: splitCSV(*outOfScope),
	})
	if err != nil {
		return err
	}
	record, err := db.CreateSessionDB(context.Background(), db.DefaultSessionsDir(), session, initialTarget)
	if err != nil {
		return err
	}
	store, err := db.OpenSession(context.Background(), db.DefaultSessionsDir(), record.Session.ID)
	if err != nil {
		return err
	}
	defer store.Close()
	runner := engine.NewRunner(store)
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
