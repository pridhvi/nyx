package nox

import (
	"flag"
	"fmt"

	"github.com/pridhvi/nox/internal/config"
)

func runConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("supported config commands: init, show")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("config init", flag.ContinueOnError)
		path := fs.String("path", config.DefaultPath(), "config file path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := config.WriteDefault(*path); err != nil {
			return err
		}
		fmt.Printf("wrote config %s\n", *path)
		return nil
	case "show":
		fs := flag.NewFlagSet("config show", flag.ContinueOnError)
		path := fs.String("path", "", "config file path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := loadConfig(*path)
		if err != nil {
			return err
		}
		fmt.Print(cfg.YAML())
		return nil
	default:
		return fmt.Errorf("supported config commands: init, show")
	}
}
