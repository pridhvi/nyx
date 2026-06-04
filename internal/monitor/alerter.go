package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/netguard"
	"github.com/pridhvi/nyx/internal/state"
)

func Alert(ctx context.Context, store *state.Store, config models.MonitorConfig, changes []models.SurfaceChange) error {
	selected := alertableChanges(config.AlertOn, changes)
	if len(selected) == 0 {
		return nil
	}
	message := fmt.Sprintf("Nyx monitor %q observed %d attack-surface change(s).", config.Name, len(selected))
	if config.NotificationConfig.SlackWebhookURL != "" {
		if err := postWebhook(ctx, config.NotificationConfig.SlackWebhookURL, map[string]string{"text": message}); err != nil {
			return err
		}
	}
	if config.NotificationConfig.DiscordWebhookURL != "" {
		if err := postWebhook(ctx, config.NotificationConfig.DiscordWebhookURL, map[string]string{"content": message}); err != nil {
			return err
		}
	}
	if config.NotificationConfig.SlackWebhookURL == "" && config.NotificationConfig.DiscordWebhookURL == "" {
		return nil
	}
	for _, change := range selected {
		if err := store.MarkSurfaceChangeAlerted(ctx, change.ID); err != nil {
			return err
		}
	}
	return nil
}

func alertableChanges(triggers []string, changes []models.SurfaceChange) []models.SurfaceChange {
	if len(triggers) == 0 {
		return nil
	}
	triggerSet := map[string]bool{}
	for _, trigger := range triggers {
		trigger = strings.TrimSpace(trigger)
		if trigger != "" {
			triggerSet[trigger] = true
		}
	}
	var selected []models.SurfaceChange
	for _, change := range changes {
		if triggerSet["any"] || triggerSet[string(change.ChangeType)] || (change.ChangeType == models.SurfaceChangeNewFinding && severityRank(change.Severity) >= severityRank(models.SeverityHigh)) {
			selected = append(selected, change)
		}
	}
	return selected
}

func postWebhook(ctx context.Context, webhookURL string, payload map[string]string) error {
	if err := validateWebhookURL(webhookURL); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func ValidateNotificationConfig(config models.MonitorNotificationConfig) error {
	if err := validateWebhookURL(config.SlackWebhookURL); err != nil {
		return fmt.Errorf("invalid Slack webhook URL: %w", err)
	}
	if err := validateWebhookURL(config.DiscordWebhookURL); err != nil {
		return fmt.Errorf("invalid Discord webhook URL: %w", err)
	}
	return nil
}

func validateWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "********" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("webhook URL must be an absolute HTTPS URL")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL must use https")
	}
	host := strings.Trim(strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."), "[]")
	if host == "localhost" || host == "metadata.google.internal" {
		return fmt.Errorf("webhook host is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && blockedWebhookIP(ip) {
		return fmt.Errorf("webhook host is not allowed")
	}
	return nil
}

func webhookHTTPClient() *http.Client {
	return netguard.NewHTTPClient(netguard.Policy{
		Service:                     "monitor webhook",
		AllowPublicWithoutAllowlist: true,
		MetadataHosts:               []string{"169.254.169.254", "metadata.google.internal"},
		BlockedIPError:              "monitor webhook host is not allowed",
		NotInAllowlistError:         "monitor webhook host is not allowed",
		ResolveError:                "monitor webhook host could not be resolved",
	}, 10*time.Second)
}

func blockedWebhookIP(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast()
}
