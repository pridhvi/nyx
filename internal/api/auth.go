package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type authLoginRequest struct {
	APIKey string `json:"api_key"`
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) == "" {
		writeJSON(w, map[string]any{"authenticated": true, "auth_enabled": false})
		return
	}
	client := clientKey(r)
	if s.authLimited(client) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
		return
	}
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.recordAuthFailure(client)
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid login request"))
		return
	}
	if req.APIKey != s.cfg.APIKey {
		s.recordAuthFailure(client)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid API key"))
		return
	}
	token, expires := s.createAuthSession()
	http.SetCookie(w, authSessionCookie(token, expires, s.secureCookie(r)))
	writeJSON(w, map[string]any{"authenticated": true, "auth_enabled": true, "expires_at": expires.UTC().Format(time.RFC3339)})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(authSessionCookieName); err == nil {
		s.deleteAuthSession(cookie.Value)
	}
	http.SetCookie(w, expiredAuthSessionCookie(s.secureCookie(r)))
	writeJSON(w, map[string]any{"authenticated": false})
}

func (s *Server) secureCookie(r *http.Request) bool {
	return s.cfg.SecureCookies || r.TLS != nil
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		if crossOriginUnsafeRequest(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("cross-origin state-changing requests are not allowed"))
			return
		}
		if strings.TrimSpace(s.cfg.APIKey) == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/auth/login" {
			next.ServeHTTP(w, r)
			return
		}
		client := clientKey(r)
		if s.authLimited(client) {
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
			return
		}
		token := r.Header.Get("X-Nyx-API-Key")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if token == s.cfg.APIKey {
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			if cookie, err := r.Cookie(authSessionCookieName); err == nil && s.validAuthSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if token != s.cfg.APIKey {
			s.recordAuthFailure(client)
			writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid or missing API key"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

const (
	authFailureWindow     = time.Minute
	authFailureLimit      = 8
	authSessionTTL        = 12 * time.Hour
	authSessionCookieName = "nyx_session"
)

func (s *Server) createAuthSession() (string, time.Time) {
	token := models.NewID() + models.NewID()
	expires := time.Now().Add(authSessionTTL)
	s.securityMu.Lock()
	s.authSessions[token] = expires
	s.securityMu.Unlock()
	return token, expires
}

func (s *Server) validAuthSession(token string) bool {
	if token == "" {
		return false
	}
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	expires, ok := s.authSessions[token]
	if !ok {
		return false
	}
	if !expires.After(now) {
		delete(s.authSessions, token)
		return false
	}
	return true
}

func (s *Server) deleteAuthSession(token string) {
	s.securityMu.Lock()
	delete(s.authSessions, token)
	s.securityMu.Unlock()
}

func authSessionCookie(token string, expires time.Time, secure bool) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure is enforced when TLS or server.secure_cookies is enabled; loopback HTTP remains supported.
		Name:     authSessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func expiredAuthSessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure mirrors the original auth cookie context while expiring the browser session.
		Name:     authSessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func (s *Server) authLimited(client string) bool {
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	failures := recentFailures(s.authFailures[client], now)
	s.authFailures[client] = failures
	return len(failures) >= authFailureLimit
}

func (s *Server) recordAuthFailure(client string) {
	now := time.Now()
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	failures := recentFailures(s.authFailures[client], now)
	failures = append(failures, now)
	s.authFailures[client] = failures
}

func recentFailures(values []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-authFailureWindow)
	next := values[:0]
	for _, value := range values {
		if value.After(cutoff) {
			next = append(next, value)
		}
	}
	return next
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func crossOriginUnsafeRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return true
	}
	return !sameHost(parsed.Host, r.Host)
}

func websocketCrossOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return true
	}
	return !sameHost(parsed.Host, r.Host)
}

func sameHost(left, right string) bool {
	leftHost, leftPort := splitHostPort(left)
	rightHost, rightPort := splitHostPort(right)
	if !strings.EqualFold(leftHost, rightHost) {
		return false
	}
	return leftPort == rightPort
}

func splitHostPort(value string) (string, string) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return strings.Trim(host, "[]"), port
	}
	return strings.Trim(value, "[]"), ""
}
