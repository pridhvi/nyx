package nyx

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/models"
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
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("built-in adapters:")
	for _, adapter := range adapters.All() {
		fmt.Printf("%s\t%s\t%s\n", adapter.ID(), adapter.Phase(), adapter.Name())
	}
	plugins, err := readGlobalCLIPlugins(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Println("global plugins:")
	for _, plugin := range plugins {
		state := "disabled"
		if plugin.Enabled {
			state = "enabled"
		}
		fmt.Printf("plugin:%s\t%s\t%s\t%s\t%s\n", plugin.Name, plugin.Phase, state, plugin.Binary, plugin.ID)
	}
	return nil
}

func runPluginsInstall(args []string) error {
	fs := flag.NewFlagSet("plugins install", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	name := fs.String("name", "", "plugin name")
	phase := fs.String("phase", "vuln_scan", "plugin phase: recon, fingerprint, enumerate, vuln_scan")
	description := fs.String("description", "", "plugin description")
	homepageURL := fs.String("homepage-url", "", "plugin homepage URL")
	disabled := fs.Bool("disabled", false, "register plugin disabled")
	if err := fs.Parse(args); err != nil {
		return err
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
	if err := validatePluginExecutable(binary); err != nil {
		return err
	}
	digest, err := adapters.PluginBinarySHA256(binary)
	if err != nil {
		return err
	}
	if !validPluginPhase(*phase) {
		return fmt.Errorf("unsupported plugin phase %q", *phase)
	}
	now := time.Now().UTC()
	plugin := models.PluginRecord{
		ID:          models.NewID(),
		Name:        pluginName,
		Binary:      binary,
		SHA256:      digest,
		Phase:       strings.TrimSpace(*phase),
		Description: strings.TrimSpace(*description),
		HomepageURL: strings.TrimSpace(*homepageURL),
		Enabled:     !*disabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	plugins, err := readGlobalCLIPlugins(*cfgPath)
	if err != nil {
		return err
	}
	for i := range plugins {
		if plugins[i].Name == plugin.Name {
			plugin.ID = plugins[i].ID
			plugin.CreatedAt = plugins[i].CreatedAt
			plugins[i] = plugin
			if err := writeGlobalCLIPlugins(*cfgPath, plugins); err != nil {
				return err
			}
			fmt.Printf("updated global plugin %s\n", plugin.Name)
			return nil
		}
	}
	plugins = append(plugins, plugin)
	if err := writeGlobalCLIPlugins(*cfgPath, plugins); err != nil {
		return err
	}
	fmt.Printf("installed global plugin %s\n", plugin.Name)
	return nil
}

func readGlobalCLIPlugins(cfgPath string) ([]models.PluginRecord, error) {
	path, err := globalCLIPluginsPath(cfgPath)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path) // #nosec G304 -- plugin registry path is resolved under the local Nyx config directory.
	if os.IsNotExist(err) {
		return []models.PluginRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var plugins []models.PluginRecord
	if err := json.Unmarshal(body, &plugins); err != nil {
		return nil, err
	}
	return plugins, nil
}

func writeGlobalCLIPlugins(cfgPath string, plugins []models.PluginRecord) error {
	path, err := globalCLIPluginsPath(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func globalCLIPluginsPath(cfgPath string) (string, error) {
	sessionDir, err := configuredSessionDir(cfgPath)
	if err != nil {
		return "", err
	}
	stateDir := sessionDir
	if filepath.Base(sessionDir) == "sessions" {
		stateDir = filepath.Dir(sessionDir)
	}
	return filepath.Join(stateDir, "plugins.json"), nil
}

func validPluginPhase(phase string) bool {
	switch strings.TrimSpace(phase) {
	case "recon", "fingerprint", "enumerate", "vuln_scan":
		return true
	default:
		return false
	}
}

func validatePluginExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("plugin binary is not accessible: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("plugin binary must be a file, got directory %s", path)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("plugin binary is not executable: %s", path)
	}
	return nil
}
