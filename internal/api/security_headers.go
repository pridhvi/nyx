package api

import (
	"net/http"
	"strings"
)

const spaContentSecurityPolicy = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src 'self' blob: data:; worker-src 'self' blob:"
const reportContentSecurityPolicy = "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; frame-ancestors 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		htmlReport := htmlReportRoute(r)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if htmlReport {
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Content-Security-Policy", reportContentSecurityPolicy)
		} else {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		if !htmlReport && spaSecurityHeadersRoute(r) {
			w.Header().Set("Content-Security-Policy", spaContentSecurityPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

func spaSecurityHeadersRoute(r *http.Request) bool {
	path := strings.TrimSpace(r.URL.Path)
	return path == "" || (!strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/ws/"))
}

func htmlReportRoute(r *http.Request) bool {
	path := strings.TrimSpace(r.URL.Path)
	return r.Method == http.MethodGet &&
		strings.HasPrefix(path, "/api/sessions/") &&
		strings.HasSuffix(path, "/report") &&
		strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "html")
}
