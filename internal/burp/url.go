package burp

import (
	"net/http"
	"time"

	"github.com/pridhvi/nyx/internal/netguard"
)

func ValidateBaseURL(baseURL string, allowedHosts []string) error {
	return netguard.ValidateHTTPURL(baseURL, endpointPolicy(allowedHosts))
}

func NewHTTPClient(allowedHosts []string, timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(endpointPolicy(allowedHosts), timeout)
}

func endpointPolicy(allowedHosts []string) netguard.Policy {
	return netguard.Policy{
		Service:                       "Burp REST",
		AllowedHosts:                  allowedHosts,
		MetadataHosts:                 []string{"metadata.google.internal"},
		AllowLoopbackWithoutAllowlist: true,
		BlockedIPError:                "private, link-local, multicast, and unspecified Burp REST endpoints require an explicit allowlist entry",
		NotInAllowlistError:           "Burp REST host is not in the configured allowlist",
		ResolveError:                  "Burp REST host could not be resolved",
		PublicHostError:               "Burp REST base URL must resolve to loopback unless explicitly allowlisted",
	}
}
