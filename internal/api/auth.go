package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
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

type authFailureState struct {
	Count       int
	LastFailure time.Time
	LockedUntil time.Time
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.APIKey) == "" {
		writeJSON(w, map[string]any{"authenticated": true, "auth_enabled": false})
		return
	}
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		keys := authLimitKeys(r, "")
		if s.authLimited(keys...) {
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
			return
		}
		s.recordAuthFailure(keys...)
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid login request"))
		return
	}
	keys := authLimitKeys(r, req.APIKey)
	if s.authLimited(keys...) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
		return
	}
	if req.APIKey != s.cfg.APIKey {
		s.recordAuthFailure(keys...)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid API key"))
		return
	}
	s.clearAuthFailures(keys...)
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
		token := r.Header.Get("X-Nyx-API-Key")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		keys := authLimitKeys(r, token)
		if s.authLimited(keys...) {
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed authentication attempts"))
			return
		}
		if token == s.cfg.APIKey {
			s.clearAuthFailures(keys...)
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			if cookie, err := r.Cookie(authSessionCookieName); err == nil && s.validAuthSession(cookie.Value) {
				s.clearAuthFailures(keys...)
				next.ServeHTTP(w, r)
				return
			}
		}
		s.recordAuthFailure(keys...)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid or missing API key"))
	})
}

const (
	authFailureLimit      = 3
	authFailureIdleReset  = 24 * time.Hour
	authLockoutBase       = 30 * time.Second
	authLockoutMax        = 30 * time.Minute
	authSessionTTL        = 12 * time.Hour
	authSessionCleanup    = time.Hour
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

func (s *Server) pruneExpiredAuthSessions(now time.Time) int {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	pruned := 0
	for token, expires := range s.authSessions {
		if !expires.After(now) {
			delete(s.authSessions, token)
			pruned++
		}
	}
	return pruned
}

func (s *Server) startAuthSessionCleanup(ctx context.Context) {
	if strings.TrimSpace(s.cfg.APIKey) == "" {
		return
	}
	slog.Debug("browser auth sessions use in-memory storage and expire on server restart", "ttl", authSessionTTL.String())
	ticker := time.NewTicker(authSessionCleanup)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if pruned := s.pruneExpiredAuthSessions(now); pruned > 0 {
					slog.Debug("pruned expired browser auth sessions", "count", pruned)
				}
				if pruned := s.pruneStaleAuthFailures(now); pruned > 0 {
					slog.Debug("pruned stale auth failure records", "count", pruned)
				}
			}
		}
	}()
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

func (s *Server) authLimited(keys ...string) bool {
	return s.authLimitedAt(time.Now(), keys...)
}

func (s *Server) authLimitedAt(now time.Time, keys ...string) bool {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	for _, key := range keys {
		state, ok := s.authFailures[key]
		if !ok {
			continue
		}
		if authFailureExpired(state, now) {
			delete(s.authFailures, key)
			continue
		}
		if state.LockedUntil.After(now) {
			return true
		}
	}
	return false
}

func (s *Server) recordAuthFailure(keys ...string) {
	s.recordAuthFailureAt(time.Now(), keys...)
}

func (s *Server) recordAuthFailureAt(now time.Time, keys ...string) {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	for _, key := range keys {
		state := s.authFailures[key]
		if authFailureExpired(state, now) {
			state = authFailureState{}
		}
		state.Count++
		state.LastFailure = now
		if state.Count >= authFailureLimit {
			state.LockedUntil = now.Add(authLockoutDuration(state.Count))
		}
		s.authFailures[key] = state
	}
}

func (s *Server) clearAuthFailures(keys ...string) {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	for _, key := range keys {
		delete(s.authFailures, key)
	}
}

func (s *Server) pruneStaleAuthFailures(now time.Time) int {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	pruned := 0
	for key, state := range s.authFailures {
		if authFailureExpired(state, now) {
			delete(s.authFailures, key)
			pruned++
		}
	}
	return pruned
}

func authFailureExpired(state authFailureState, now time.Time) bool {
	if state.LastFailure.IsZero() {
		return true
	}
	return !state.LockedUntil.After(now) && now.Sub(state.LastFailure) >= authFailureIdleReset
}

func authLockoutDuration(count int) time.Duration {
	if count < authFailureLimit {
		return 0
	}
	shift := count - authFailureLimit
	if shift > 10 {
		shift = 10
	}
	duration := authLockoutBase * time.Duration(1<<shift)
	if duration > authLockoutMax {
		return authLockoutMax
	}
	return duration
}

func authLimitKeys(r *http.Request, presentedSecret string) []string {
	client := "client:" + clientKey(r)
	secret := strings.TrimSpace(presentedSecret)
	if secret == "" {
		return []string{client, client + ":missing"}
	}
	return []string{client, "credential:" + authSecretFingerprint(secret)}
}

func authSecretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
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
