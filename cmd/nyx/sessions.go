package nyx

import (
	"archive/zip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/pridhvi/nyx/internal/db"
)

func runSessions(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported sessions commands: list, show <id>, delete <id>, export <id> --output <file.zip>")
	}
	switch args[0] {
	case "list":
		return listSessions()
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("sessions show requires a session id")
		}
		return showSession(args[1])
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("sessions delete requires a session id")
		}
		return deleteSession(args[1])
	case "findings":
		if len(args) < 2 {
			return fmt.Errorf("sessions findings requires a session id")
		}
		return listFindings(args[1])
	case "runs":
		if len(args) < 2 {
			return fmt.Errorf("sessions runs requires a session id")
		}
		return listToolRuns(args[1])
	case "export":
		return exportSession(args[1:])
	default:
		return fmt.Errorf("supported sessions commands: list, show <id>, delete <id>, findings <id>, runs <id>, export <id> --output <file.zip>")
	}
}

func listSessions() error {
	sessionDir, err := configuredSessionDir("")
	if err != nil {
		return err
	}
	records, err := db.ListSessions(context.Background(), sessionDir)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("no sessions found")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATUS\tMODE\tTARGET\tCREATED\tTARGETS\tFINDINGS")
	for _, record := range records {
		s := record.Session
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			s.ID,
			s.Status,
			s.Mode,
			s.TargetInput,
			s.CreatedAt.Format("2006-01-02 15:04:05"),
			s.TargetCount,
			s.FindingCount,
		)
	}
	return w.Flush()
}

func showSession(sessionID string) error {
	sessionDir, cfgErr := configuredSessionDir("")
	if cfgErr != nil {
		return cfgErr
	}
	store, err := db.OpenSession(context.Background(), sessionDir, sessionID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	targets, err := store.ListTargets(context.Background(), session.ID)
	if err != nil {
		return err
	}
	fmt.Printf("id: %s\n", session.ID)
	fmt.Printf("name: %s\n", session.Name)
	fmt.Printf("status: %s\n", session.Status)
	fmt.Printf("mode: %s\n", session.Mode)
	fmt.Printf("target: %s\n", session.TargetInput)
	fmt.Printf("created: %s\n", session.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("db: %s\n", store.Path())
	fmt.Println("targets:")
	for _, target := range targets {
		fmt.Printf("  - %s %s:%d alive=%t discovered_by=%s\n", target.Protocol, target.Host, target.Port, target.IsAlive, target.DiscoveredBy)
	}
	return nil
}

func deleteSession(sessionID string) error {
	sessionDir, cfgErr := configuredSessionDir("")
	if cfgErr != nil {
		return cfgErr
	}
	if err := db.DeleteSession(context.Background(), sessionDir, sessionID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
		return err
	}
	fmt.Printf("deleted session %s\n", sessionID)
	return nil
}

func listFindings(sessionID string) error {
	sessionDir, cfgErr := configuredSessionDir("")
	if cfgErr != nil {
		return cfgErr
	}
	store, err := db.OpenSession(context.Background(), sessionDir, sessionID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
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
	if len(findings) == 0 {
		fmt.Println("no findings found")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tTOOL\tTITLE\tURL")
	for _, finding := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", finding.Severity, finding.ToolID, finding.Title, finding.URL)
	}
	return w.Flush()
}

func listToolRuns(sessionID string) error {
	sessionDir, cfgErr := configuredSessionDir("")
	if cfgErr != nil {
		return cfgErr
	}
	store, err := db.OpenSession(context.Background(), sessionDir, sessionID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	runs, err := store.ListToolRuns(context.Background(), session.ID)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		fmt.Println("no tool runs found")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TOOL\tEXIT\tDURATION_MS\tFINDINGS\tSTARTED")
	for _, run := range runs {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n", run.ToolID, run.ExitCode, run.DurationMS, run.FindingCount, run.StartedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}

func exportSession(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("sessions export requires a session id")
	}
	sessionID := args[0]
	fs := flag.NewFlagSet("sessions export", flag.ContinueOnError)
	output := fs.String("output", "", "output zip file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*output) == "" {
		return fmt.Errorf("sessions export requires --output <file.zip>")
	}
	sessionDir, cfgErr := configuredSessionDir("")
	if cfgErr != nil {
		return cfgErr
	}
	store, err := db.OpenSession(context.Background(), sessionDir, sessionID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
		return err
	}
	if _, err := store.GetSession(context.Background()); err != nil {
		store.Close()
		return err
	}
	root := filepath.Dir(store.Path())
	if err := store.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil && filepath.Dir(*output) != "." {
		return err
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	archive := zip.NewWriter(file)
	defer archive.Close()
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootHandle.Close()
	runsCount := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "runs"+string(filepath.Separator)) {
			runsCount++
		}
		writer, err := archive.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		input, err := rootHandle.Open(rel)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("exported session %s to %s\n", sessionID, *output)
	if runsCount == 0 {
		fmt.Println("note: no run log files were included")
	}
	return nil
}

func configuredSessionDir(configPath string) (string, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return "", err
	}
	return firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), nil
}
