package llm

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

func AllowedHostsFromEnv() []string {
	return splitList(os.Getenv("NYX_LLM_ALLOWED_HOSTS"))
}

func ValidateBaseURL(baseURL string, allowedHosts []string) error {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("base_url must be an absolute http or https URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("base_url must use http or https")
	}
	host := normalizeHost(parsed.Hostname())
	allowed := hostAllowed(host, allowedHosts)
	if isMetadataHost(host) && !allowed {
		return fmt.Errorf("metadata service endpoints are not allowed")
	}
	if len(allowedHosts) > 0 && !allowed {
		return fmt.Errorf("base_url host is not in the configured allowlist")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedEndpointIP(ip) && !allowed {
			return fmt.Errorf("private, loopback, link-local, multicast, and unspecified LLM endpoints require an explicit allowlist entry")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("base_url host could not be resolved")
	}
	for _, ip := range ips {
		if isBlockedEndpointIP(ip) && !allowed {
			return fmt.Errorf("private, loopback, link-local, multicast, and unspecified LLM endpoints require an explicit allowlist entry")
		}
	}
	return nil
}

func hostAllowed(host string, allowed []string) bool {
	host = normalizeHost(host)
	for _, entry := range allowed {
		entry = normalizeHost(entry)
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			suffix := strings.TrimPrefix(entry, "*")
			if strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isMetadataHost(host string) bool {
	return host == "metadata.google.internal"
}

func isBlockedEndpointIP(ip net.IP) bool {
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast()
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
