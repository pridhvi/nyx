package burp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func ValidateBaseURL(baseURL string, allowedHosts []string) error {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("Burp REST base URL must be an absolute http or https URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("Burp REST base URL must use http or https")
	}
	host := normalizeAllowedHost(parsed.Hostname())
	allowed := hostAllowed(host, allowedHosts)
	if isMetadataHost(host) && !allowed {
		return fmt.Errorf("metadata service endpoints are not allowed for Burp REST")
	}
	if len(allowedHosts) > 0 && !allowed {
		return fmt.Errorf("Burp REST host is not in the configured allowlist")
	}
	if ip := net.ParseIP(host); ip != nil {
		return validateBurpEndpointIP(ip, allowed)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("Burp REST host could not be resolved")
	}
	for _, ip := range ips {
		if err := validateBurpEndpointIP(ip, allowed); err != nil {
			return err
		}
	}
	return nil
}

func validateBurpEndpointIP(ip net.IP, allowed bool) error {
	if allowed {
		return nil
	}
	if ip.IsLoopback() {
		return nil
	}
	if ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("private, link-local, multicast, and unspecified Burp REST endpoints require an explicit allowlist entry")
	}
	return fmt.Errorf("Burp REST base URL must resolve to loopback unless explicitly allowlisted")
}

func hostAllowed(host string, allowed []string) bool {
	host = normalizeAllowedHost(host)
	for _, entry := range allowed {
		entry = normalizeAllowedHost(entry)
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			if strings.HasSuffix(host, strings.TrimPrefix(entry, "*")) {
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

func normalizeAllowedHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isMetadataHost(host string) bool {
	return host == "metadata.google.internal"
}
