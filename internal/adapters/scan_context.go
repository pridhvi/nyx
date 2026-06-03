package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/pridhvi/nyx/internal/models"
)

type scanContext struct {
	RouteSeeds                []string
	AuthHeaders               map[string]string
	AuthCookies               map[string]string
	CookieHeader              string
	AuthProfile               map[string]any
	SafeActiveChecks          map[string]any
	SecondaryAuthHeaders      map[string]string
	SecondaryAuthCookies      map[string]string
	SecondaryAuthCookieHeader string
}

func inputScanContext(input AdapterInput) scanContext {
	params := map[string]any{}
	if input.Session.ToolParameters != nil && input.Session.ToolParameters[models.SessionScanOptionsKey] != nil {
		params = input.Session.ToolParameters[models.SessionScanOptionsKey]
	}
	ctx := scanContext{
		RouteSeeds:                compactStrings(anyStringList(params["route_seeds"])),
		AuthHeaders:               anyStringMap(params["auth_headers"]),
		AuthCookies:               anyStringMap(params["auth_cookies"]),
		CookieHeader:              strings.TrimSpace(toString(params["auth_cookie_header"])),
		AuthProfile:               anyMap(params["auth_profile"]),
		SafeActiveChecks:          anyMap(params["safe_active_checks"]),
		SecondaryAuthHeaders:      anyStringMap(params["secondary_auth_headers"]),
		SecondaryAuthCookies:      anyStringMap(params["secondary_auth_cookies"]),
		SecondaryAuthCookieHeader: strings.TrimSpace(toString(params["secondary_auth_cookie_header"])),
	}
	if len(ctx.SafeActiveChecks) == 0 && len(ctx.AuthProfile) > 0 {
		ctx.SafeActiveChecks = anyMap(ctx.AuthProfile["safe_active_checks"])
	}
	if seedFile := strings.TrimSpace(toString(params["route_seed_file"])); seedFile != "" {
		ctx.RouteSeeds = append(ctx.RouteSeeds, readRouteSeedFile(seedFile)...)
	}
	ctx.RouteSeeds = dedupeStrings(ctx.RouteSeeds)
	return ctx
}

func anyMap(value any) map[string]any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			key = strings.TrimSpace(key)
			if key != "" {
				out[key] = strings.TrimSpace(item)
			}
		}
		return out
	default:
		return nil
	}
}

func anyStringList(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, toString(item))
		}
		return out
	case string:
		if strings.Contains(typed, "\n") {
			return strings.Split(typed, "\n")
		}
		return strings.Split(typed, ",")
	default:
		return []string{toString(typed)}
	}
}

func anyStringMap(value any) map[string]string {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]string:
		return typed
	case map[string]any:
		out := make(map[string]string, len(typed))
		for key, item := range typed {
			key = strings.TrimSpace(key)
			text := strings.TrimSpace(toString(item))
			if key != "" && text != "" {
				out[key] = text
			}
		}
		return out
	default:
		return nil
	}
}

func readRouteSeedFile(path string) []string {
	file, err := os.Open(path) // #nosec G304 -- route seed path is an explicit operator-selected local input file.
	if err != nil {
		return nil
	}
	defer file.Close()
	var routes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		routes = append(routes, line)
		if len(routes) >= 10000 {
			break
		}
	}
	return routes
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func seededRouteValues(input AdapterInput) []string {
	return inputScanContext(input).RouteSeeds
}

func seededURLs(input AdapterInput) []string {
	var urls []string
	for _, seed := range seededRouteValues(input) {
		raw := normalizeSeedURL(input.Target, seed)
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		if ok, _ := targetInScope(input, parsed.Hostname()); !ok {
			continue
		}
		urls = append(urls, raw)
	}
	return dedupeStrings(urls)
}

func seededPathValues(input AdapterInput) []string {
	var paths []string
	for _, raw := range seededURLs(input) {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		path := strings.TrimPrefix(parsed.EscapedPath(), "/")
		if path == "" {
			continue
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		paths = append(paths, path)
	}
	return dedupeStrings(paths)
}

func normalizeSeedURL(target models.Target, seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	if parsed, err := url.Parse(seed); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			return parsed.String()
		}
		return ""
	}
	base := strings.TrimRight(targetURL(target), "/")
	if strings.HasPrefix(seed, "?") {
		return base + "/" + seed
	}
	if !strings.HasPrefix(seed, "/") {
		seed = "/" + seed
	}
	return base + seed
}

func newHTTPRequestWithAuth(ctx context.Context, input AdapterInput, method, rawURL string, body io.Reader, userAgent string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	applyAuthToRequest(input, req)
	return req, nil
}

func applyAuthToRequest(input AdapterInput, req *http.Request) {
	scanCtx := inputScanContext(input)
	applyRequestAuth(req, scanCtx.AuthHeaders, scanCtx.AuthCookies, scanCtx.CookieHeader)
}

func applySecondaryAuthToRequest(input AdapterInput, req *http.Request) bool {
	scanCtx := inputScanContext(input)
	if len(scanCtx.SecondaryAuthHeaders) == 0 && len(scanCtx.SecondaryAuthCookies) == 0 && scanCtx.SecondaryAuthCookieHeader == "" {
		return false
	}
	applyRequestAuth(req, scanCtx.SecondaryAuthHeaders, scanCtx.SecondaryAuthCookies, scanCtx.SecondaryAuthCookieHeader)
	return true
}

func hasSecondaryAuth(input AdapterInput) bool {
	scanCtx := inputScanContext(input)
	return len(scanCtx.SecondaryAuthHeaders) > 0 || len(scanCtx.SecondaryAuthCookies) > 0 || scanCtx.SecondaryAuthCookieHeader != ""
}

func applyRequestAuth(req *http.Request, headers, cookies map[string]string, cookieHeader string) {
	for name, value := range headers {
		if strings.TrimSpace(name) != "" && value != "" {
			req.Header.Set(name, value)
		}
	}
	if cookieHeader == "" && len(cookies) > 0 {
		var parts []string
		for _, name := range sortedMapKeys(cookies) {
			value := cookies[name]
			if strings.TrimSpace(name) != "" && value != "" {
				parts = append(parts, strings.TrimSpace(name)+"="+value)
			}
		}
		cookieHeader = strings.Join(parts, "; ")
	}
	if cookieHeader != "" && req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", cookieHeader)
	}
}

type commandAuthMaterial struct {
	HeaderLines  []string
	CookieHeader string
}

func commandAuthMaterialFor(input AdapterInput) commandAuthMaterial {
	scanCtx := inputScanContext(input)
	cookieHeader := scanCtx.CookieHeader
	if cookieHeader == "" && len(scanCtx.AuthCookies) > 0 {
		var parts []string
		for _, name := range sortedMapKeys(scanCtx.AuthCookies) {
			value := scanCtx.AuthCookies[name]
			if strings.TrimSpace(name) != "" && value != "" {
				parts = append(parts, strings.TrimSpace(name)+"="+value)
			}
		}
		cookieHeader = strings.Join(parts, "; ")
	}
	var headerLines []string
	for _, name := range sortedMapKeys(scanCtx.AuthHeaders) {
		value := scanCtx.AuthHeaders[name]
		if strings.TrimSpace(name) != "" && value != "" {
			headerLines = append(headerLines, strings.TrimSpace(name)+": "+value)
		}
	}
	return commandAuthMaterial{HeaderLines: headerLines, CookieHeader: cookieHeader}
}

func authFileCommandArgs(input AdapterInput, toolID, rawURL string) ([]string, func(), error) {
	material := commandAuthMaterialFor(input)
	if len(material.HeaderLines) == 0 && material.CookieHeader == "" {
		return nil, func() {}, nil
	}
	switch toolID {
	case "ffuf":
		path, cleanup, err := writeAuthRawRequestFile(rawURL, material)
		if err != nil {
			return nil, cleanup, err
		}
		scheme := "http"
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		return []string{"-request", path, "-request-proto", scheme}, cleanup, nil
	case "sqlmap":
		path, cleanup, err := writeAuthRawRequestFile(rawURL, material)
		if err != nil {
			return nil, cleanup, err
		}
		args := []string{"-r", path}
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Scheme == "https" {
			args = append(args, "--force-ssl")
		}
		return args, cleanup, nil
	case "dalfox":
		path, cleanup, err := writeDalfoxAuthConfig(material)
		if err != nil {
			return nil, cleanup, err
		}
		return []string{"--config", path}, cleanup, nil
	default:
		return nil, func() {}, nil
	}
}

func writeAuthRawRequestFile(rawURL string, material commandAuthMaterial) (string, func(), error) {
	cleanup := func() {}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", cleanup, err
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	file, err := os.CreateTemp("", "nyx-auth-request-*.txt")
	if err != nil {
		return "", cleanup, err
	}
	cleanup = func() { _ = os.Remove(file.Name()) }
	lines := []string{"GET " + path + " HTTP/1.1", "Host: " + parsed.Host}
	for _, line := range material.HeaderLines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "host:") {
			continue
		}
		lines = append(lines, line)
	}
	if material.CookieHeader != "" {
		lines = append(lines, "Cookie: "+material.CookieHeader)
	}
	lines = append(lines, "Connection: close", "", "")
	if _, err := file.WriteString(strings.Join(lines, "\r\n")); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return file.Name(), cleanup, nil
}

func writeDalfoxAuthConfig(material commandAuthMaterial) (string, func(), error) {
	cleanup := func() {}
	file, err := os.CreateTemp("", "nyx-dalfox-auth-*.json")
	if err != nil {
		return "", cleanup, err
	}
	cleanup = func() { _ = os.Remove(file.Name()) }
	config := map[string]any{}
	if len(material.HeaderLines) > 0 {
		var headers []string
		for _, line := range material.HeaderLines {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "cookie:") {
				headers = append(headers, line)
			}
		}
		if len(headers) > 0 {
			config["header"] = headers
		}
	}
	if material.CookieHeader != "" {
		config["cookie"] = material.CookieHeader
	}
	body, err := json.Marshal(config)
	if err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return file.Name(), cleanup, nil
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func redactCommandArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		switch out[i] {
		case "-H", "-b", "--headers", "--cookie":
			if i+1 < len(out) {
				out[i+1] = "********"
				i++
			}
		}
	}
	return out
}
