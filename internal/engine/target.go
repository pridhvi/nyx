package engine

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

func NewInitialTarget(sessionID, targetInput string) models.Target {
	host, port, protocol := ParseTargetInput(targetInput)
	return models.Target{
		ID:           models.NewID(),
		SessionID:    sessionID,
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		IsAlive:      false,
		DiscoveredBy: "user",
		CreatedAt:    time.Now().UTC(),
	}
}

func ParseTargetInput(targetInput string) (host string, port int, protocol string) {
	protocol = "https"
	raw := strings.TrimSpace(targetInput)
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		raw = parsed.Host
		if parsed.Scheme != "" {
			protocol = parsed.Scheme
		}
	}
	if splitHost, splitPort, err := net.SplitHostPort(raw); err == nil {
		raw = splitHost
		if p, err := strconv.Atoi(splitPort); err == nil {
			port = p
		}
	}
	if port == 0 {
		switch protocol {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	return strings.Trim(strings.ToLower(raw), "[]"), port, protocol
}
