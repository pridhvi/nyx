package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

type Subfinder struct{}

func NewSubfinder() Subfinder                       { return Subfinder{} }
func (Subfinder) ID() string                        { return "subfinder" }
func (Subfinder) Name() string                      { return "Subfinder" }
func (Subfinder) Phase() Phase                      { return PhaseRecon }
func (Subfinder) DependsOn() []string               { return nil }
func (Subfinder) ShouldRun(input AdapterInput) bool { return input.Target.Host != "" }
func (a Subfinder) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	domain := scopedRootDomain(input)
	args := []string{"-silent", "-d", domain}
	if ok, reason := targetInScope(input, domain); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "subfinder", args...)
	targets := parseHostLines(input, a.ID(), result.Stdout, "https", 443)
	return AdapterOutput{NewTargets: targets, ToolRun: finishToolRun(run, result, len(targets))}, nil
}

type DNSX struct{}

func NewDNSX() DNSX                            { return DNSX{} }
func (DNSX) ID() string                        { return "dnsx" }
func (DNSX) Name() string                      { return "DNSX" }
func (DNSX) Phase() Phase                      { return PhaseRecon }
func (DNSX) DependsOn() []string               { return nil }
func (DNSX) ShouldRun(input AdapterInput) bool { return input.Target.Host != "" }
func (a DNSX) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	domain := scopedRootDomain(input)
	args := []string{"-silent", "-a", "-resp", "-d", domain}
	if ok, reason := targetInScope(input, domain); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "dnsx", args...)
	targets := parseDNSXTargets(input, result.Stdout)
	return AdapterOutput{NewTargets: targets, ToolRun: finishToolRun(run, result, len(targets))}, nil
}

type Naabu struct{}

func NewNaabu() Naabu             { return Naabu{} }
func (Naabu) ID() string          { return "naabu" }
func (Naabu) Name() string        { return "Naabu" }
func (Naabu) Phase() Phase        { return PhaseRecon }
func (Naabu) DependsOn() []string { return nil }
func (Naabu) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.Host != ""
}
func (a Naabu) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	args := []string{"-silent", "-host", input.Target.Host}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "naabu", args...)
	targets := parseNaabuTargets(input, result.Stdout)
	findings := parseNaabuFindings(input, result.Stdout)
	return AdapterOutput{NewTargets: targets, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type HTTPX struct{}

func NewHTTPX() HTTPX                           { return HTTPX{} }
func (HTTPX) ID() string                        { return "httpx" }
func (HTTPX) Name() string                      { return "HTTPX" }
func (HTTPX) Phase() Phase                      { return PhaseRecon }
func (HTTPX) DependsOn() []string               { return []string{"subfinder", "naabu"} }
func (HTTPX) ShouldRun(input AdapterInput) bool { return input.Target.Host != "" }
func (a HTTPX) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	args := []string{"-silent", "-json", "-title", "-tech-detect", "-u", input.Target.Host}
	if ok, reason := targetInScope(input, input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "httpx", args...)
	targets, techs, findings := parseHTTPXOutput(input, result.Stdout)
	return AdapterOutput{NewTargets: targets, Technologies: techs, Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type Whois struct{}

func NewWhois() Whois                           { return Whois{} }
func (Whois) ID() string                        { return "whois" }
func (Whois) Name() string                      { return "Whois" }
func (Whois) Phase() Phase                      { return PhaseRecon }
func (Whois) DependsOn() []string               { return nil }
func (Whois) ShouldRun(input AdapterInput) bool { return input.Target.Host != "" }
func (a Whois) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	domain := scopedRootDomain(input)
	args := []string{domain}
	if ok, reason := targetInScope(input, domain); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 30*time.Second, "whois", args...)
	findings := parseWhoisFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type WaybackURLs struct{}

func NewWaybackURLs() WaybackURLs                     { return WaybackURLs{} }
func (WaybackURLs) ID() string                        { return "waybackurls" }
func (WaybackURLs) Name() string                      { return "Waybackurls" }
func (WaybackURLs) Phase() Phase                      { return PhaseRecon }
func (WaybackURLs) DependsOn() []string               { return []string{"subfinder"} }
func (WaybackURLs) ShouldRun(input AdapterInput) bool { return input.Target.Host != "" }
func (a WaybackURLs) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	domain := scopedRootDomain(input)
	args := []string{domain}
	if ok, reason := targetInScope(input, domain); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, 60*time.Second, "waybackurls", args...)
	findings := parseURLLineFindings(input, a.ID(), result.Stdout, "Archived URL discovered", []string{"wayback", "url"})
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type CrtSH struct{}

func NewCrtSH() CrtSH                     { return CrtSH{} }
func (CrtSH) ID() string                  { return "crtsh" }
func (CrtSH) Name() string                { return "crt.sh" }
func (CrtSH) Phase() Phase                { return PhaseRecon }
func (CrtSH) DependsOn() []string         { return nil }
func (CrtSH) ShouldRun(AdapterInput) bool { return false }
func (a CrtSH) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	domain := scopedRootDomain(input)
	args := []string{domain}
	if ok, reason := targetInScope(input, domain); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, fmt.Sprintf("crt.sh returned HTTP %d", resp.StatusCode), 1)}, nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, err.Error(), 1)}, nil
	}
	targets := parseCrtSHTargets(input, rows)
	run.StdoutRaw = fmt.Sprintf("crt.sh targets: %d", len(targets))
	run.FindingCount = len(targets)
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{NewTargets: targets, ToolRun: run}, nil
}

func parseHostLines(input AdapterInput, sourceTool, raw, protocol string, port int) []models.Target {
	seen := map[string]bool{}
	var targets []models.Target
	for _, line := range strings.Split(raw, "\n") {
		host := normalizeHost(line)
		if host == "" || seen[host] {
			continue
		}
		if ok, _ := targetInScope(input, host); !ok {
			continue
		}
		seen[host] = true
		targets = append(targets, models.Target{
			ID:           models.NewID(),
			SessionID:    input.Session.ID,
			Host:         host,
			Port:         port,
			Protocol:     protocol,
			DiscoveredBy: sourceTool,
			CreatedAt:    time.Now().UTC(),
		})
	}
	return targets
}

func parseDNSXTargets(input AdapterInput, raw string) []models.Target {
	return parseHostLines(input, "dnsx", raw, "https", 443)
}

func parseNaabuTargets(input AdapterInput, raw string) []models.Target {
	seen := map[string]bool{}
	var targets []models.Target
	for _, line := range strings.Split(raw, "\n") {
		host, port := parseHostPort(line)
		if host == "" || port <= 0 || seen[fmt.Sprintf("%s:%d", host, port)] {
			continue
		}
		if ok, _ := targetInScope(input, host); !ok {
			continue
		}
		protocol := "tcp"
		if port == 80 {
			protocol = "http"
		}
		if port == 443 {
			protocol = "https"
		}
		seen[fmt.Sprintf("%s:%d", host, port)] = true
		targets = append(targets, models.Target{
			ID:           models.NewID(),
			SessionID:    input.Session.ID,
			Host:         host,
			Port:         port,
			Protocol:     protocol,
			IsAlive:      true,
			DiscoveredBy: "naabu",
			CreatedAt:    time.Now().UTC(),
		})
	}
	return targets
}

func parseNaabuFindings(input AdapterInput, raw string) []models.Finding {
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		host, port := parseHostPort(line)
		if host == "" || port <= 0 {
			continue
		}
		if ok, _ := targetInScope(input, host); !ok {
			continue
		}
		findings = append(findings, externalFinding(
			input,
			"naabu",
			models.FindingTypeExposure,
			models.SeverityInfo,
			fmt.Sprintf("Open TCP port %d", port),
			fmt.Sprintf("Naabu reported %s:%d open.", host, port),
			"Confirm the exposed service is intended and access-controlled.",
			raw,
			map[string]any{"host": host, "port": port, "protocol": "tcp"},
			[]string{"naabu", "open-port"},
		))
	}
	return findings
}

type httpxRecord struct {
	URL          string   `json:"url"`
	Input        string   `json:"input"`
	Host         string   `json:"host"`
	Port         string   `json:"port"`
	Scheme       string   `json:"scheme"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	Technologies []string `json:"tech"`
}

func parseHTTPXOutput(input AdapterInput, raw string) ([]models.Target, []models.Technology, []models.Finding) {
	var targets []models.Target
	var techs []models.Technology
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record httpxRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		host, scheme, port := httpxTargetParts(record)
		if host == "" {
			continue
		}
		if ok, _ := targetInScope(input, host); !ok {
			continue
		}
		targetID := models.NewID()
		targets = append(targets, models.Target{
			ID:           targetID,
			SessionID:    input.Session.ID,
			Host:         host,
			Port:         port,
			Protocol:     scheme,
			IsAlive:      true,
			DiscoveredBy: "httpx",
			CreatedAt:    time.Now().UTC(),
		})
		for _, tech := range record.Technologies {
			tech = strings.TrimSpace(tech)
			if tech == "" {
				continue
			}
			techs = append(techs, models.Technology{
				ID:         models.NewID(),
				TargetID:   targetID,
				Name:       tech,
				Category:   "web",
				Confidence: 0.7,
				SourceTool: "httpx",
			})
		}
		findings = append(findings, externalFinding(input, "httpx", models.FindingTypeInfo, models.SeverityInfo, "Live HTTP service discovered", "httpx reported a live HTTP service.", "Review the service exposure and fingerprinting details.", raw, map[string]any{"url": record.URL, "status_code": record.StatusCode, "title": record.Title}, []string{"httpx", "live-http"}))
	}
	return targets, techs, findings
}

func parseWhoisFindings(input AdapterInput, raw string) []models.Finding {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	normalized := map[string]any{
		"registrar": firstField(raw, "Registrar:"),
		"org":       firstField(raw, "OrgName:"),
		"country":   firstField(raw, "Country:"),
	}
	return []models.Finding{externalFinding(input, "whois", models.FindingTypeInfo, models.SeverityInfo, "WHOIS registration information discovered", "WHOIS returned registration metadata for the target domain.", "Review ownership and registrar details during scoping.", raw, normalized, []string{"whois", "osint"})}
}

func parseURLLineFindings(input AdapterInput, toolID, raw, title string, tags []string) []models.Finding {
	seen := map[string]bool{}
	var findings []models.Finding
	for _, line := range strings.Split(raw, "\n") {
		value := strings.TrimSpace(line)
		if value == "" || seen[value] {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			continue
		}
		if ok, _ := targetInScope(input, parsed.Hostname()); !ok {
			continue
		}
		seen[value] = true
		findings = append(findings, externalFinding(input, toolID, models.FindingTypeInfo, models.SeverityInfo, title, fmt.Sprintf("%s discovered %s.", toolID, value), "Review discovered URLs for in-scope attack surface.", raw, map[string]any{"url": value, "host": parsed.Hostname(), "path": parsed.Path}, tags))
	}
	return findings
}

func parseCrtSHTargets(input AdapterInput, rows []struct {
	NameValue string `json:"name_value"`
}) []models.Target {
	var raw []string
	for _, row := range rows {
		raw = append(raw, strings.Split(row.NameValue, "\n")...)
	}
	return parseHostLines(input, "crtsh", strings.Join(raw, "\n"), "https", 443)
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "*.")
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			value = parsed.Hostname()
		}
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, "*."))
	if value == "" {
		return ""
	}
	value = strings.Fields(value)[0]
	value = strings.Trim(value, "[]")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.ToLower(strings.Trim(value, "."))
}

func parseHostPort(value string) (string, int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		parts := strings.Split(value, ":")
		if len(parts) < 2 {
			return normalizeHost(value), 0
		}
		host = strings.Join(parts[:len(parts)-1], ":")
		portValue = parts[len(parts)-1]
	}
	port, _ := strconv.Atoi(portValue)
	return normalizeHost(host), port
}

func httpxTargetParts(record httpxRecord) (string, string, int) {
	host := normalizeHost(record.Host)
	scheme := strings.TrimSpace(record.Scheme)
	port, _ := strconv.Atoi(record.Port)
	if record.URL != "" {
		parsed, err := url.Parse(record.URL)
		if err == nil {
			if host == "" {
				host = parsed.Hostname()
			}
			if scheme == "" {
				scheme = parsed.Scheme
			}
			if port == 0 {
				port, _ = strconv.Atoi(parsed.Port())
			}
		}
	}
	if scheme == "" {
		scheme = "https"
	}
	if port == 0 {
		if scheme == "http" {
			port = 80
		} else if scheme == "https" {
			port = 443
		}
	}
	return host, scheme, port
}

func rootDomain(host string) string {
	host = normalizeHost(host)
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func scopedRootDomain(input AdapterInput) string {
	host := normalizeHost(input.Target.Host)
	root := rootDomain(host)
	if ok, _ := targetInScope(input, root); ok {
		return root
	}
	return host
}

func firstField(raw, prefix string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func targetInScope(input AdapterInput, host string) (bool, string) {
	if input.Scope == nil {
		return true, ""
	}
	return input.Scope.IsInScope(host)
}
