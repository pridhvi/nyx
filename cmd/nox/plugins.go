package nox

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/kanini/nox/internal/adapters"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/models"
)

func runPlugins(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported plugins commands: list, install")
	}
	switch args[0] {
	case "list":
		return runPluginsList(args[1:])
	case "install":
		return runPluginsInstall(args[1:])
	default:
		return fmt.Errorf("supported plugins commands: list, install")
	}
}

func runPluginsList(args []string) error {
	fs := flag.NewFlagSet("plugins list", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session id for configured plugins")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("built-in adapters:")
	for _, adapter := range adapters.All() {
		fmt.Printf("%s\t%s\t%s\n", adapter.ID(), adapter.Phase(), adapter.Name())
	}
	if strings.TrimSpace(*sessionID) == "" {
		return nil
	}
	store, err := db.OpenSession(context.Background(), db.DefaultSessionsDir(), *sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	plugins, err := store.ListPlugins(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("configured plugins:")
	for _, plugin := range plugins {
		state := "disabled"
		if plugin.Enabled {
			state = "enabled"
		}
		fmt.Printf("plugin:%s\t%s\t%s\t%s\n", plugin.Name, state, plugin.Binary, plugin.ID)
	}
	return nil
}

func runPluginsInstall(args []string) error {
	fs := flag.NewFlagSet("plugins install", flag.ContinueOnError)
	sessionID := fs.String("session", "", "session id to register plugin with")
	name := fs.String("name", "", "plugin name")
	disabled := fs.Bool("disabled", false, "register plugin disabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*sessionID) == "" {
		return fmt.Errorf("--session is required")
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("plugins install requires a plugin binary path")
	}
	binary, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	pluginName := strings.TrimSpace(*name)
	if pluginName == "" {
		pluginName = strings.TrimSuffix(filepath.Base(binary), filepath.Ext(binary))
	}
	now := time.Now().UTC()
	plugin := models.PluginRecord{
		ID:        models.NewID(),
		Name:      pluginName,
		Binary:    binary,
		Enabled:   !*disabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	store, err := db.OpenSession(context.Background(), db.DefaultSessionsDir(), *sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.UpsertPlugin(context.Background(), plugin); err != nil {
		return err
	}
	fmt.Printf("installed plugin %s for session %s\n", plugin.Name, *sessionID)
	return nil
}
