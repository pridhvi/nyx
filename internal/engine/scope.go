package engine

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type ScopeChecker struct {
	inNets   []*net.IPNet
	inHosts  []string
	outNets  []*net.IPNet
	outHosts []string
}

func NewScopeChecker(inScope, outOfScope []string) (*ScopeChecker, error) {
	s := &ScopeChecker{}
	if err := s.addAll(inScope, true); err != nil {
		return nil, err
	}
	if err := s.addAll(outOfScope, false); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ScopeChecker) IsInScope(raw string) (bool, string) {
	if _, cidr, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
		for _, blocked := range s.outNets {
			if blocked.String() == cidr.String() || blocked.Contains(cidr.IP) {
				return false, fmt.Sprintf("%s matches out-of-scope CIDR %s", cidr.String(), blocked.String())
			}
		}
		for _, allowed := range s.inNets {
			if allowed.String() == cidr.String() || allowed.Contains(cidr.IP) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s does not match configured scope", cidr.String())
	}
	host := normalizeHost(raw)
	if host == "" {
		return false, "empty host"
	}
	ip := net.ParseIP(host)
	for _, blocked := range s.outHosts {
		if hostMatches(host, blocked) {
			return false, fmt.Sprintf("%s matches out-of-scope host %s", host, blocked)
		}
	}
	if ip != nil {
		for _, blocked := range s.outNets {
			if blocked.Contains(ip) {
				return false, fmt.Sprintf("%s is inside out-of-scope CIDR %s", host, blocked.String())
			}
		}
	}
	if len(s.inHosts) == 0 && len(s.inNets) == 0 {
		return false, "no in-scope targets configured"
	}
	for _, allowed := range s.inHosts {
		if hostMatches(host, allowed) {
			return true, ""
		}
	}
	if ip != nil {
		for _, allowed := range s.inNets {
			if allowed.Contains(ip) {
				return true, ""
			}
		}
	}
	return false, fmt.Sprintf("%s does not match configured scope", host)
}

func (s *ScopeChecker) addAll(items []string, inScope bool) error {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(item); err == nil {
			if inScope {
				s.inNets = append(s.inNets, cidr)
			} else {
				s.outNets = append(s.outNets, cidr)
			}
			continue
		}
		host := normalizeHost(item)
		if host == "" {
			return fmt.Errorf("invalid scope entry %q", item)
		}
		if inScope {
			s.inHosts = append(s.inHosts, host)
		} else {
			s.outHosts = append(s.outHosts, host)
		}
	}
	return nil
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = u.Host
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return strings.Trim(strings.ToLower(raw), "[]")
}

func hostMatches(host, pattern string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}
	return host == pattern
}
