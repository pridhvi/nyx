package monitor

import (
	"testing"

	"github.com/pridhvi/nyx/internal/models"
)

func TestValidateNotificationConfigRejectsUnsafeWebhookTargets(t *testing.T) {
	tests := []models.MonitorNotificationConfig{
		{SlackWebhookURL: "http://hooks.slack.com/services/test"},
		{SlackWebhookURL: "https://127.0.0.1/services/test"},
		{SlackWebhookURL: "https://10.0.0.1/services/test"},
		{SlackWebhookURL: "https://169.254.169.254/latest/meta-data"},
		{DiscordWebhookURL: "https://localhost/webhook"},
	}
	for _, test := range tests {
		if err := ValidateNotificationConfig(test); err == nil {
			t.Fatalf("expected unsafe webhook rejection for %#v", test)
		}
	}
}

func TestValidateNotificationConfigAllowsPublicHTTPSWebhook(t *testing.T) {
	if err := ValidateNotificationConfig(models.MonitorNotificationConfig{
		SlackWebhookURL:   "https://hooks.slack.com/services/T000/B000/secret",
		DiscordWebhookURL: "https://discord.com/api/webhooks/123/secret",
	}); err != nil {
		t.Fatalf("expected public HTTPS webhooks to be accepted: %v", err)
	}
}
