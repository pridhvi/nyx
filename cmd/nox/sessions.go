package nox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/kanini/nox/internal/db"
)

func runSessions(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported sessions commands: list, show <id>, delete <id>")
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
	default:
		return fmt.Errorf("supported sessions commands: list, show <id>, delete <id>")
	}
}

func listSessions() error {
	records, err := db.ListSessions(context.Background(), db.DefaultSessionsDir())
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
	store, err := db.OpenSession(context.Background(), db.DefaultSessionsDir(), sessionID)
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
	if err := db.DeleteSession(context.Background(), db.DefaultSessionsDir(), sessionID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("session %s not found", sessionID)
		}
		return err
	}
	fmt.Printf("deleted session %s\n", sessionID)
	return nil
}
