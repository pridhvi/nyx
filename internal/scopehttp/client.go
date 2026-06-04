package scopehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ScopeValidator interface {
	IsInScope(raw string) (bool, string)
}

type Options struct {
	Timeout  time.Duration
	ProxyURL string
	Base     *http.Client
}

func NewClient(scope ScopeValidator, options Options) (*http.Client, error) {
	base := options.Base
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if options.Timeout > 0 && (client.Timeout <= 0 || client.Timeout < options.Timeout) {
		client.Timeout = options.Timeout
	}
	proxy, err := parseProxyURL(options.ProxyURL)
	if err != nil {
		return nil, err
	}
	if transport, ok := cloneTransport(client.Transport); ok {
		if proxy != nil {
			transport.Proxy = http.ProxyURL(proxy)
		} else {
			transport.Proxy = nil
			transport.DialContext = scopedDialContext(scope, transport.DialContext)
		}
		client.Transport = transport
	}
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := CheckURL(scope, req.URL); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &client, nil
}

func CheckURL(scope ScopeValidator, rawURL *url.URL) error {
	if scope == nil || rawURL == nil {
		return nil
	}
	host := rawURL.Hostname()
	if host == "" {
		return fmt.Errorf("redirect target is missing a host")
	}
	if ok, reason := scope.IsInScope(host); !ok {
		if strings.TrimSpace(reason) == "" {
			reason = "host is outside configured scope"
		}
		return fmt.Errorf("redirect target %s rejected by scope: %s", host, reason)
	}
	return nil
}

func cloneTransport(transport http.RoundTripper) (*http.Transport, bool) {
	if transport == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), true
	}
	if typed, ok := transport.(*http.Transport); ok {
		return typed.Clone(), true
	}
	return nil, false
}

func scopedDialContext(scope ScopeValidator, previous func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	dial := previous
	if dial == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if scope != nil {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if ok, reason := scope.IsInScope(host); !ok {
				if strings.TrimSpace(reason) == "" {
					reason = "host is outside configured scope"
				}
				return nil, fmt.Errorf("dial target %s rejected by scope: %s", host, reason)
			}
		}
		return dial(ctx, network, address)
	}
}

func parseProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	switch parsed.Scheme {
	case "http", "https", "socks5":
		return parsed, nil
	default:
		return nil, fmt.Errorf("invalid proxy URL")
	}
}
