package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Policy struct {
	Service                       string
	AllowedHosts                  []string
	MetadataHosts                 []string
	AllowLoopbackWithoutAllowlist bool
	AllowPublicWithoutAllowlist   bool
	BlockedIPError                string
	NotInAllowlistError           string
	ResolveError                  string
	PublicHostError               string
}

func ValidateHTTPURL(raw string, policy Policy) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("%s base URL must be an absolute http or https URL", serviceName(policy))
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s base URL must use http or https", serviceName(policy))
	}
	return validateHost(context.Background(), parsed.Hostname(), policy)
}

func NewHTTPClient(policy Policy, timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = guardedDialContext(policy)
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := ValidateHTTPURL(req.URL.String(), policy); err != nil {
				return err
			}
			return nil
		},
	}
}

func validateHost(ctx context.Context, rawHost string, policy Policy) error {
	host := normalizeHost(rawHost)
	if host == "" {
		return fmt.Errorf("%s base URL must include a host", serviceName(policy))
	}
	allowed := hostAllowed(host, policy.AllowedHosts)
	if isMetadataHost(host, policy.MetadataHosts) && !allowed {
		return errorOrDefault(policy.BlockedIPError, "metadata service endpoints are not allowed")
	}
	if len(policy.AllowedHosts) > 0 && !allowed {
		return errorOrDefault(policy.NotInAllowlistError, fmt.Sprintf("%s host is not in the configured allowlist", serviceName(policy)))
	}
	if ip := net.ParseIP(host); ip != nil {
		return validateEndpointIP(ip, allowed, policy)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return errorOrDefault(policy.ResolveError, fmt.Sprintf("%s host could not be resolved", serviceName(policy)))
	}
	for _, ip := range ips {
		if err := validateEndpointIP(ip.IP, allowed, policy); err != nil {
			return err
		}
	}
	return nil
}

func guardedDialContext(policy Policy) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		host = normalizeHost(host)
		if err := validateHost(ctx, host, policy); err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errorOrDefault(policy.ResolveError, fmt.Sprintf("%s host could not be resolved", serviceName(policy)))
		}
		var lastErr error
		for _, resolved := range ips {
			if err := validateEndpointIP(resolved.IP, hostAllowed(host, policy.AllowedHosts), policy); err != nil {
				return nil, err
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func validateEndpointIP(ip net.IP, allowed bool, policy Policy) error {
	if allowed {
		return nil
	}
	if ip.IsLoopback() && policy.AllowLoopbackWithoutAllowlist {
		return nil
	}
	if isBlockedEndpointIP(ip) {
		return errorOrDefault(policy.BlockedIPError, fmt.Sprintf("%s endpoint requires an explicit allowlist entry", serviceName(policy)))
	}
	if policy.AllowPublicWithoutAllowlist {
		return nil
	}
	return errorOrDefault(policy.PublicHostError, fmt.Sprintf("%s base URL must resolve to an allowed host", serviceName(policy)))
}

func hostAllowed(host string, allowed []string) bool {
	host = normalizeHost(host)
	for _, entry := range allowed {
		entry = normalizeHost(entry)
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

func normalizeHost(host string) string {
	return strings.Trim(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."), "[]")
}

func isMetadataHost(host string, metadataHosts []string) bool {
	for _, entry := range metadataHosts {
		if normalizeHost(entry) == host {
			return true
		}
	}
	return false
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

func errorOrDefault(message, fallback string) error {
	if strings.TrimSpace(message) != "" {
		return fmt.Errorf("%s", message)
	}
	return fmt.Errorf("%s", fallback)
}

func serviceName(policy Policy) string {
	if strings.TrimSpace(policy.Service) != "" {
		return strings.TrimSpace(policy.Service)
	}
	return "outbound"
}
