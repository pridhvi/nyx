package llm

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/netguard"
)

func AllowedHostsFromEnv() []string {
	return splitList(os.Getenv("NYX_LLM_ALLOWED_HOSTS"))
}

func ValidateBaseURL(baseURL string, allowedHosts []string) error {
	return netguard.ValidateHTTPURL(baseURL, endpointPolicy(allowedHosts))
}

func NewHTTPClient(allowedHosts []string, timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(endpointPolicy(allowedHosts), timeout)
}

func endpointPolicy(allowedHosts []string) netguard.Policy {
	return netguard.Policy{
		Service:                     "LLM",
		AllowedHosts:                allowedHosts,
		MetadataHosts:               []string{"metadata.google.internal"},
		AllowPublicWithoutAllowlist: true,
		BlockedIPError:              "private, loopback, link-local, multicast, and unspecified LLM endpoints require an explicit allowlist entry",
		NotInAllowlistError:         "base_url host is not in the configured allowlist",
		ResolveError:                "base_url host could not be resolved",
	}
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
