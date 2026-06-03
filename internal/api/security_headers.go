package api

import (
	"net/http"
	"strings"
)

const spaContentSecurityPolicy = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; frame-src 'self' blob: data:; worker-src 'self' blob:"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if spaSecurityHeadersRoute(r) {
			w.Header().Set("Content-Security-Policy", spaContentSecurityPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

func spaSecurityHeadersRoute(r *http.Request) bool {
	path := strings.TrimSpace(r.URL.Path)
	return path == "" || (!strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/ws/"))
}
