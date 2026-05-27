package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/pridhvi/nyx/internal/models"
)

type DOMXSSCheck struct{}

type domXSSCandidate struct {
	RawURL    string
	Parameter string
}

func NewDOMXSSCheck() DOMXSSCheck { return DOMXSSCheck{} }
func (DOMXSSCheck) ID() string    { return "dom-xss-check" }
func (DOMXSSCheck) Name() string  { return "DOM XSS Check" }
func (DOMXSSCheck) Phase() Phase  { return PhaseVulnScan }
func (DOMXSSCheck) DependsOn() []string {
	return []string{"reflected-xss-check", "stored-xss-check"}
}
func (DOMXSSCheck) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && liveHTTP(input) && len(domXSSCandidates(input, 10)) > 0
}
func (a DOMXSSCheck) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	candidates := domXSSCandidates(input, 10)
	args := domXSSCandidateArgs(candidates)
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	raw := []string{fmt.Sprintf("candidates=%d", len(candidates))}
	if allowed, reason := domXSSAllowed(input); !allowed {
		raw = append(raw, "skip_reason="+reason)
		finishBrowserlessToolRun(&run, raw, "", 0)
		return AdapterOutput{ToolRun: run}, nil
	}
	browserPath, err := domXSSBrowserPath(input)
	if err != nil {
		finishBrowserlessToolRun(&run, raw, err.Error(), 127)
		return AdapterOutput{ToolRun: run}, nil
	}
	if input.Scope != nil && HasAuthProfile(input.Session) {
		result, err := ResolveSessionAuth(ctx, input.Session, input.Target, input.Scope)
		if err == nil && result.Applied {
			input.Session = result.Session
			raw = append(raw, "auth_refreshed=true")
		} else if err != nil {
			raw = append(raw, "auth_refresh_error="+err.Error())
		}
	}
	marker := domXSSMarker(input)
	payloads := domXSSPayloads(marker)
	var findings []models.Finding
	for _, candidate := range candidates {
		for payloadIndex, payload := range payloads {
			probeURL := mutateDOMXSSCandidate(candidate, payload)
			if ok, reason := targetInScopeURL(input, probeURL); !ok {
				raw = append(raw, fmt.Sprintf("%s#%s payload=%d skip_reason=%s", candidate.RawURL, candidate.Parameter, payloadIndex, reason))
				continue
			}
			result, err := runDOMXSSBrowserProbe(ctx, input, browserPath, probeURL, marker)
			if err != nil {
				raw = append(raw, fmt.Sprintf("%s#%s payload=%d browser_error=%s", candidate.RawURL, candidate.Parameter, payloadIndex, err))
				continue
			}
			raw = append(raw, fmt.Sprintf("%s#%s payload=%d marker=%t observed=%s", candidate.RawURL, candidate.Parameter, payloadIndex, result.Confirmed, result.Observed))
			if !result.Confirmed {
				continue
			}
			evidence := result.HTML
			if len(evidence) > 8192 {
				evidence = evidence[:8192]
			}
			finding := externalFinding(input, a.ID(), models.FindingTypeVulnerability, models.SeverityHigh, "DOM XSS marker confirmed", "A seeded DOM-controlled parameter executed a browser-side marker payload in an explicitly benchmark-safe target.", "Avoid writing untrusted URL, hash, or storage values into DOM sinks. Use textContent/safe DOM APIs, strict allow-lists, and a restrictive Content Security Policy.", evidence, map[string]any{"url": probeURL, "source_url": candidate.RawURL, "parameter": candidate.Parameter, "validated": true, "marker": marker, "payload_index": payloadIndex}, []string{"xss", "dom-xss", "browser-validated", "validated"})
			finding.URL = probeURL
			finding.Parameter = candidate.Parameter
			finding.Method = http.MethodGet
			finding.Status = "confirmed"
			finding.Confidence = 0.9
			findings = append(findings, finding)
			break
		}
		if len(findings) > 0 {
			break
		}
	}
	run.RawStdout = strings.Join(raw, "\n")
	run.ExitCode = 0
	run.FindingCount = len(findings)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{Findings: findings, ToolRun: run}, nil
}

type domXSSBrowserResult struct {
	Confirmed bool
	Observed  string
	HTML      string
}

func runDOMXSSBrowserProbe(ctx context.Context, input AdapterInput, browserPath, rawURL, marker string) (domXSSBrowserResult, error) {
	userDataDir, err := os.MkdirTemp("", "nyx-dom-xss-*")
	if err != nil {
		return domXSSBrowserResult{}, err
	}
	defer os.RemoveAll(userDataDir)
	timeout := commandTimeout(input, 25*time.Second)
	wait := domXSSWaitDuration(input)
	allocOptions := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserPath),
		chromedp.Headless,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.UserDataDir(userDataDir),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("mute-audio", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOptions...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	runCtx, cancelRun := context.WithTimeout(browserCtx, timeout)
	defer cancelRun()
	var observed string
	var html string
	actions := []chromedp.Action{
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return applyDOMXSSBrowserAuth(ctx, input, rawURL)
		}),
		chromedp.Navigate(rawURL),
		chromedp.Sleep(wait),
		chromedp.Evaluate(`(function(){return document.documentElement.getAttribute("data-nyx-dom-xss") || window.__nyxDOMXSSMarker || "";})()`, &observed),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	}
	if err := chromedp.Run(runCtx, actions...); err != nil {
		return domXSSBrowserResult{}, err
	}
	return domXSSBrowserResult{Confirmed: observed == marker, Observed: observed, HTML: html}, nil
}

func applyDOMXSSBrowserAuth(ctx context.Context, input AdapterInput, rawURL string) error {
	scanCtx := inputScanContext(input)
	headers := network.Headers{}
	for name, value := range scanCtx.AuthHeaders {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" || strings.EqualFold(name, "cookie") {
			continue
		}
		headers[name] = value
	}
	if len(headers) > 0 {
		if err := network.SetExtraHTTPHeaders(headers).Do(ctx); err != nil {
			return err
		}
	}
	cookies := map[string]string{}
	for name, value := range scanCtx.AuthCookies {
		if strings.TrimSpace(name) != "" && strings.TrimSpace(value) != "" {
			cookies[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	for name, value := range parseCookieHeader(scanCtx.CookieHeader) {
		cookies[name] = value
	}
	for name, value := range cookies {
		if err := network.SetCookie(name, value).WithURL(rawURL).WithPath("/").Do(ctx); err != nil {
			return err
		}
	}
	return nil
}

func domXSSAllowed(input AdapterInput) (bool, string) {
	toolAllowed := toolParamBool(input, "enabled") ||
		toolParamBool(input, "allow_active") ||
		toolParamBool(input, "allow_dom_xss")
	toolIntentionallyVulnerable := toolParamBool(input, "intentionally_vulnerable")
	toolNonProduction := toolParamBool(input, "non_production")
	checks := inputScanContext(input).SafeActiveChecks
	profileAllowed := boolMapValue(checks, "allow_dom_xss") || boolMapValue(checks, "dom_xss")
	profileIntentionallyVulnerable := boolMapValue(checks, "intentionally_vulnerable")
	profileNonProduction := boolMapValue(checks, "non_production")
	if (toolAllowed || profileAllowed) && (toolIntentionallyVulnerable || profileIntentionallyVulnerable) && (toolNonProduction || profileNonProduction) {
		return true, ""
	}
	return false, "active_dom_xss_requires_intentionally_vulnerable_non_production_opt_in"
}

func domXSSCandidates(input AdapterInput, limit int) []domXSSCandidate {
	var candidates []domXSSCandidate
	seen := map[string]bool{}
	add := func(rawURL string) {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" {
			return
		}
		if ok, _ := targetInScope(input, parsed.Hostname()); !ok {
			return
		}
		for _, param := range domXSSParameterNames(parsed) {
			key := rawURL + "\x00" + param
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, domXSSCandidate{RawURL: rawURL, Parameter: param})
			if limit > 0 && len(candidates) >= limit {
				return
			}
		}
	}
	for _, rawURL := range seededURLs(input) {
		if !looksLikeAPIRoute(rawURL) && looksLikeDOMXSSSurface(rawURL) {
			add(rawURL)
			if limit > 0 && len(candidates) >= limit {
				return candidates
			}
		}
	}
	for _, route := range sourceValues(input.SourceFindings, models.SourceKindRoute) {
		if !looksLikeAPIRoute(route) && looksLikeDOMXSSSurface(route) {
			add(normalizeSeedURL(input.Target, route))
			if limit > 0 && len(candidates) >= limit {
				return candidates
			}
		}
	}
	return candidates
}

func domXSSParameterNames(parsed *url.URL) []string {
	seen := map[string]bool{}
	var params []string
	keys := sortedQueryKeys(parsed.Query())
	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		seen[key] = true
		params = append(params, key)
	}
	if parsed.Fragment != "" {
		_, fragment := fragmentQueryValues(parsed.Fragment)
		for _, key := range sortedQueryKeys(fragment) {
			if key != "" && !seen["#"+key] {
				seen["#"+key] = true
				params = append(params, "#"+key)
			}
		}
	}
	return params
}

func looksLikeDOMXSSSurface(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "dom") ||
		strings.Contains(lower, "xss_d") ||
		strings.Contains(lower, "hash") ||
		strings.Contains(lower, "fragment") ||
		strings.Contains(lower, "client") ||
		strings.Contains(lower, "#/") ||
		strings.Contains(lower, "search")
}

func mutateDOMXSSCandidate(candidate domXSSCandidate, payload string) string {
	parsed, err := url.Parse(candidate.RawURL)
	if err != nil {
		return candidate.RawURL
	}
	if strings.HasPrefix(candidate.Parameter, "#") {
		key := strings.TrimPrefix(candidate.Parameter, "#")
		prefix, fragment := fragmentQueryValues(parsed.Fragment)
		fragment.Set(key, payload)
		parsed.Fragment = ""
		return parsed.String() + "#" + prefix + encodeDOMXSSParams(fragment, key)
	}
	query := parsed.Query()
	query.Set(candidate.Parameter, payload)
	parsed.RawQuery = encodeDOMXSSParams(query, candidate.Parameter)
	return parsed.String()
}

func fragmentQueryValues(fragment string) (string, url.Values) {
	if index := strings.Index(fragment, "?"); index >= 0 {
		values, _ := url.ParseQuery(fragment[index+1:])
		return fragment[:index+1], values
	}
	values, _ := url.ParseQuery(fragment)
	return "", values
}

func encodeDOMXSSParams(values url.Values, payloadKey string) string {
	var parts []string
	for _, key := range sortedQueryKeys(values) {
		for _, value := range values[key] {
			encodedValue := url.QueryEscape(value)
			if key == payloadKey {
				encodedValue = encodeDOMXSSLocationValue(value)
			}
			parts = append(parts, url.QueryEscape(key)+"="+encodedValue)
		}
	}
	return strings.Join(parts, "&")
}

func encodeDOMXSSLocationValue(value string) string {
	escaped := strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
	return strings.NewReplacer(
		"%2F", "/",
		"%2f", "/",
		"%3D", "=",
		"%3d", "=",
		"%3B", ";",
		"%3b", ";",
		"%2C", ",",
		"%2c", ",",
	).Replace(escaped)
}

func domXSSCandidateArgs(candidates []domXSSCandidate) []string {
	args := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		args = append(args, candidate.RawURL+"#"+candidate.Parameter)
	}
	return args
}

func domXSSMarker(input AdapterInput) string {
	id := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, input.Session.ID)
	if len(id) > 12 {
		id = id[:12]
	}
	if id == "" {
		id = "marker"
	}
	return "nyxdom" + id
}

func domXSSPayload(marker string) string {
	js := fmt.Sprintf(`document.documentElement.setAttribute('data-nyx-dom-xss','%s');window.__nyxDOMXSSMarker='%s'`, marker, marker)
	return `</option></select><svg onload="` + js + `"></svg><select><option>`
}

func domXSSPayloads(marker string) []string {
	js := fmt.Sprintf(`document.documentElement.setAttribute('data-nyx-dom-xss','%s');window.__nyxDOMXSSMarker='%s'`, marker, marker)
	topJS := fmt.Sprintf(`top.document.documentElement.setAttribute('data-nyx-dom-xss','%s');top.__nyxDOMXSSMarker='%s'`, marker, marker)
	return []string{
		`<img src=x onerror="` + js + `">`,
		`<iframe src="javascript:` + topJS + `"></iframe>`,
		domXSSPayload(marker),
	}
}

func domXSSBrowserPath(input AdapterInput) (string, error) {
	if configured := strings.TrimSpace(toolParamString(input, "browser_path")); configured != "" {
		if filepath.IsAbs(configured) {
			if stat, err := os.Stat(configured); err == nil && !stat.IsDir() {
				return configured, nil
			}
		}
		if path, err := exec.LookPath(configured); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("configured browser_path %q was not found", configured)
	}
	for _, envName := range []string{"NYX_BROWSER_PATH", "CHROME_PATH", "CHROMIUM_PATH"} {
		if configured := strings.TrimSpace(os.Getenv(envName)); configured != "" {
			if filepath.IsAbs(configured) {
				if stat, err := os.Stat(configured); err == nil && !stat.IsDir() {
					return configured, nil
				}
			}
			if path, err := exec.LookPath(configured); err == nil {
				return path, nil
			}
		}
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "microsoft-edge"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no Chrome/Chromium browser found for dom-xss-check")
}

func domXSSWaitDuration(input AdapterInput) time.Duration {
	ms := toolParamInt(input, "wait_ms", 0)
	if ms <= 0 {
		ms = intMapValue(inputScanContext(input).SafeActiveChecks, "dom_xss_wait_ms")
	}
	if ms <= 0 {
		ms = 500
	}
	if ms > 3000 {
		ms = 3000
	}
	return time.Duration(ms) * time.Millisecond
}

func parseCookieHeader(header string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name != "" && value != "" {
			out[name] = value
		}
	}
	return out
}

func finishBrowserlessToolRun(run *models.ToolRun, stdout []string, stderr string, exitCode int) {
	run.RawStdout = strings.Join(stdout, "\n")
	run.RawStderr = stderr
	run.ExitCode = exitCode
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
}
