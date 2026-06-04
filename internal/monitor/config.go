package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/models"
	"github.com/robfig/cron/v3"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func NormalizeConfig(config models.MonitorConfig, now time.Time) (models.MonitorConfig, error) {
	config.Name = strings.TrimSpace(config.Name)
	config.TargetInput = strings.TrimSpace(config.TargetInput)
	config.Schedule = strings.TrimSpace(config.Schedule)
	if config.ID == "" {
		config.ID = models.NewID()
	}
	if config.Name == "" {
		config.Name = config.TargetInput
	}
	if config.TargetInput == "" {
		return models.MonitorConfig{}, fmt.Errorf("target_input is required")
	}
	if config.Schedule == "" {
		config.Schedule = "@daily"
	}
	if _, err := cronParser.Parse(config.Schedule); err != nil {
		return models.MonitorConfig{}, fmt.Errorf("invalid schedule: %w", err)
	}
	if len(config.EnabledPhases) == 0 && len(config.EnabledTools) == 0 {
		config.EnabledPhases = []string{string(adapters.PhaseRecon), string(adapters.PhaseFingerprint)}
	}
	if config.RunnerOptions.PerToolConcurrency == 0 {
		config.RunnerOptions.PerToolConcurrency = 1
	}
	if err := ValidateNotificationConfig(config.NotificationConfig); err != nil {
		return models.MonitorConfig{}, err
	}
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now
	next, err := NextRun(config.Schedule, now)
	if err != nil {
		return models.MonitorConfig{}, err
	}
	config.NextRunAt = &next
	return config, nil
}

func NextRun(schedule string, from time.Time) (time.Time, error) {
	parsed, err := cronParser.Parse(strings.TrimSpace(schedule))
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Next(from), nil
}

func ValidateAlertTriggers(triggers []string) error {
	allowed := map[string]bool{
		string(models.SurfaceChangeNewHost):         true,
		string(models.SurfaceChangeNewService):      true,
		string(models.SurfaceChangeNewTechnology):   true,
		string(models.SurfaceChangeEndpointChanged): true,
		string(models.SurfaceChangeNewFinding):      true,
		"any":                                       true,
	}
	for _, trigger := range triggers {
		trigger = strings.TrimSpace(trigger)
		if trigger == "" {
			continue
		}
		if !allowed[trigger] {
			return fmt.Errorf("unsupported alert trigger %q", trigger)
		}
	}
	return nil
}
