package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/adapters"
	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

type toolParameter struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Default     any      `json:"default,omitempty"`
	Options     []string `json:"options,omitempty"`
	Description string   `json:"description,omitempty"`
}

type toolRecord struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	HomepageURL    string          `json:"homepage_url"`
	Phase          string          `json:"phase"`
	DependsOn      []string        `json:"depends_on"`
	Kind           string          `json:"kind"`
	DefaultEnabled bool            `json:"default_enabled"`
	Installed      bool            `json:"installed"`
	BinaryPath     string          `json:"binary_path"`
	Version        string          `json:"version"`
	InstallHint    string          `json:"install_hint"`
	Parameters     []toolParameter `json:"parameters"`
	LastRun        *models.ToolRun `json:"last_run,omitempty"`
}

func (s *Server) tools(w http.ResponseWriter, r *http.Request) {
	registered := adapters.All()
	lastRuns := map[string]models.ToolRun{}
	if sessionID := strings.TrimSpace(r.URL.Query().Get("session_id")); sessionID != "" {
		if store, err := db.OpenSession(r.Context(), s.cfg.SessionDir, sessionID); err == nil {
			if session, err := store.GetSession(r.Context()); err == nil {
				if runs, err := store.ListToolRuns(r.Context(), session.ID); err == nil {
					for _, run := range runs {
						lastRuns[run.ToolID] = run
					}
				}
			}
			_ = store.Close()
		}
	}
	tools := make([]toolRecord, 0, len(registered))
	for _, adapter := range registered {
		record := s.toolRecord(adapter)
		if run, ok := lastRuns[adapter.ID()]; ok {
			record.LastRun = &run
		}
		tools = append(tools, record)
	}
	for _, plugin := range s.enabledGlobalPlugins() {
		record := s.toolRecord(adapters.NewConfiguredPlugin(plugin))
		record.Kind = "plugin"
		record.Installed = validatePluginBinary(plugin.Binary) == nil
		record.BinaryPath = plugin.Binary
		record.Description = plugin.Description
		record.HomepageURL = plugin.HomepageURL
		record.InstallHint = firstNonEmpty(plugin.Description, "Global plugin.")
		tools = append(tools, record)
	}
	writeJSON(w, tools)
}

func (s *Server) toolRecord(adapter adapters.Adapter) toolRecord {
	id := adapter.ID()
	deps := adapter.DependsOn()
	if deps == nil {
		deps = []string{}
	}
	binary := binaryNameForTool(id)
	parameters := parametersForTool(id)
	if parameters == nil {
		parameters = []toolParameter{}
	}
	path := ""
	installed := true
	version := ""
	kind := "builtin_http"
	if binary != "" {
		kind = "subprocess"
		path, installed = s.detectToolBinary(id, binary)
		if installed {
			version = detectVersion(path)
		}
	}
	return toolRecord{
		ID:             id,
		Name:           adapter.Name(),
		Description:    descriptionForTool(id),
		HomepageURL:    homepageForTool(id),
		Phase:          string(adapter.Phase()),
		DependsOn:      deps,
		Kind:           kind,
		DefaultEnabled: id != "crtsh",
		Installed:      installed,
		BinaryPath:     path,
		Version:        version,
		InstallHint:    installHintForTool(id, binary),
		Parameters:     parameters,
	}
}

func (s *Server) detectToolBinary(toolID, binary string) (string, bool) {
	for _, candidate := range []string{s.cfg.ToolPaths[toolID], s.cfg.ToolPaths[binary]} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	path, err := exec.LookPath(binary)
	return path, err == nil
}

func validateTools(toolIDs []string) error {
	for _, id := range toolIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if strings.HasPrefix(id, "plugin:") {
			continue
		}
		if strings.HasPrefix(id, "audit/") {
			if _, ok := adapters.GetStatic(strings.TrimPrefix(id, "audit/")); !ok {
				return fmt.Errorf("unknown tool %q", id)
			}
			continue
		}
		if _, ok := adapters.Get(id); !ok {
			return fmt.Errorf("unknown tool %q", id)
		}
	}
	return nil
}

func binaryNameForTool(id string) string {
	switch id {
	case "subfinder":
		return "subfinder"
	case "dnsx":
		return "dnsx"
	case "naabu":
		return "naabu"
	case "httpx":
		return "httpx"
	case "whois":
		return "whois"
	case "waybackurls":
		return "waybackurls"
	case "nmap":
		return "nmap"
	case "ffuf":
		return "ffuf"
	case "whatweb":
		return "whatweb"
	case "nuclei-tech", "nuclei-vuln":
		return "nuclei"
	case "testssl":
		return "testssl.sh"
	case "wpscan":
		return "wpscan"
	case "droopescan":
		return "droopescan"
	case "arjun":
		return "arjun"
	case "linkfinder":
		return "linkfinder"
	case "gitleaks":
		return "gitleaks"
	case "sqlmap":
		return "sqlmap"
	case "dalfox":
		return "dalfox"
	case "ssrfmap":
		return "ssrfmap"
	case "jwt-tool":
		return "jwt_tool"
	case "nikto":
		return "nikto"
	default:
		return ""
	}
}

func installHintForTool(id, binary string) string {
	if binary == "" {
		return "Built into Nyx."
	}
	return "Install " + binary + " or configure tools." + id + " in the Nyx config."
}

func descriptionForTool(id string) string {
	descriptions := map[string]string{
		"http-probe":              "Checks whether scoped HTTP and HTTPS endpoints respond and records basic reachability evidence.",
		"security-headers":        "Inspects common browser security headers and records missing or weak protections.",
		"crtsh":                   "Queries certificate transparency data for scoped hostnames.",
		"subfinder":               "Discovers subdomains from passive sources.",
		"dnsx":                    "Resolves and validates discovered DNS names.",
		"naabu":                   "Performs scoped TCP port discovery.",
		"httpx":                   "Probes HTTP services and captures response metadata.",
		"whois":                   "Collects WHOIS registration data for scoped domains.",
		"waybackurls":             "Collects historical URLs from public archives.",
		"whatweb":                 "Fingerprints web technologies and server-side frameworks.",
		"nuclei-tech":             "Runs Nuclei technology-detection templates.",
		"testssl":                 "Checks TLS protocol and certificate configuration.",
		"graphql-introspection":   "Attempts safe GraphQL introspection discovery.",
		"graphql-security-review": "Reviews GraphQL schema, console, batching, suggestions, and resolver-shaped risk signals without destructive exploit execution.",
		"openapi-discovery":       "Discovers OpenAPI and Swagger metadata endpoints.",
		"wpscan":                  "Fingerprints WordPress installations and common exposure signals.",
		"droopescan":              "Fingerprints Drupal, Joomla, and other CMS exposure signals.",
		"ffuf":                    "Runs scoped content discovery against web targets.",
		"arjun":                   "Discovers HTTP parameters with safe probing.",
		"linkfinder":              "Extracts hidden JavaScript endpoints from scoped web responses.",
		"gitleaks":                "Scans collected code and text artifacts for secret patterns.",
		"js-secrets":              "Looks for likely secrets in JavaScript responses.",
		"cors-check":              "Checks CORS policy behavior on scoped HTTP targets.",
		"cloud-buckets":           "Checks for scoped cloud storage bucket exposure patterns.",
		"nuclei-vuln":             "Runs Nuclei vulnerability templates against scoped targets.",
		"sqlmap":                  "Runs conservative SQL injection checks with scoped inputs.",
		"dalfox":                  "Runs scoped XSS checks.",
		"ssrfmap":                 "Runs scoped SSRF checks where input evidence supports it.",
		"jwt-tool":                "Checks JWT structure and common token weaknesses.",
		"oauth-check":             "Checks OAuth and OIDC metadata for common misconfigurations.",
		"brute-force-check":       "Validates explicitly configured benchmark credentials with a strict attempt budget only on intentionally vulnerable non-production targets.",
		"reflected-xss-check":     "Safely validates seeded query parameters for reflected XSS markers.",
		"dom-xss-check":           "Uses an installed Chrome/Chromium browser to validate seeded DOM XSS markers, including SPA hash/search routes, only on intentionally vulnerable non-production targets.",
		"stored-xss-check":        "Validates seeded stored-XSS forms only when explicitly marked intentionally vulnerable and non-production.",
		"open-redirect-check":     "Safely validates seeded redirect-like parameters and operator-seeded external redirect URLs without following external redirects.",
		"sqli-check":              "Safely validates seeded query parameters for SQL injection with bounded boolean and error canaries.",
		"file-inclusion-check":    "Safely validates seeded file/path parameters with bounded local hosts-file marker probes.",
		"command-injection-check": "Validates seeded command-like forms only when explicitly marked intentionally vulnerable and non-production.",
		"upload-check":            "Safely validates file upload endpoints with a harmless text marker file.",
		"idor-check":              "Checks seeded object identifier routes for adjacent-object access and optional secondary-identity replay.",
		"workflow-assist":         "Surfaces seeded high-value workflow, business-control, CAPTCHA-protected sensitive forms, and CAPTCHA answer exposure for manual review without submitting state changes.",
		"csp-review":              "Surfaces seeded CSP bypass review candidates without attempting exploit execution.",
		"csrf-check":              "Analyzes seeded state-changing forms for missing anti-CSRF token fields without submitting them.",
		"weak-session-check":      "Samples seeded session-related routes for predictable cookie or token values with tight limits.",
		"ssti-check":              "Performs safe server-side template injection checks.",
		"xxe-fuzz":                "Performs safe XML entity expansion checks without external entity exfiltration.",
		"nikto":                   "Runs Nikto web server checks against scoped HTTP services.",
		"cve-intel":               "Correlates discovered technologies with CVE intelligence.",
		"attack-vector-engine":    "Builds deterministic attack chains from normalized findings.",
		"llm-analysis":            "Adds optional local LLM annotations to findings and attack vectors.",
		"nmap":                    "Runs scoped network service detection.",
	}
	if value, ok := descriptions[id]; ok {
		return value
	}
	return "Adapter-provided scanner."
}

func homepageForTool(id string) string {
	homepages := map[string]string{
		"crtsh":        "https://crt.sh/",
		"subfinder":    "https://github.com/projectdiscovery/subfinder",
		"dnsx":         "https://github.com/projectdiscovery/dnsx",
		"naabu":        "https://github.com/projectdiscovery/naabu",
		"httpx":        "https://github.com/projectdiscovery/httpx",
		"waybackurls":  "https://github.com/tomnomnom/waybackurls",
		"whatweb":      "https://github.com/urbanadventurer/WhatWeb",
		"nuclei-tech":  "https://github.com/projectdiscovery/nuclei",
		"nuclei-vuln":  "https://github.com/projectdiscovery/nuclei",
		"testssl":      "https://github.com/testssl/testssl.sh",
		"wpscan":       "https://github.com/wpscanteam/wpscan",
		"droopescan":   "https://github.com/SamJoan/droopescan",
		"ffuf":         "https://github.com/ffuf/ffuf",
		"arjun":        "https://github.com/s0md3v/Arjun",
		"linkfinder":   "https://github.com/GerbenJavado/LinkFinder",
		"gitleaks":     "https://github.com/gitleaks/gitleaks",
		"sqlmap":       "https://github.com/sqlmapproject/sqlmap",
		"dalfox":       "https://github.com/hahwul/dalfox",
		"ssrfmap":      "https://github.com/swisskyrepo/SSRFmap",
		"jwt-tool":     "https://github.com/ticarpi/jwt_tool",
		"nikto":        "https://github.com/sullo/nikto",
		"nmap":         "https://nmap.org/",
		"llm-analysis": "https://github.com/sashabaranov/go-openai",
	}
	return homepages[id]
}

func detectVersion(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil || len(out) == 0 {
		out, err = exec.CommandContext(ctx, path, "-version").CombinedOutput()
		if err != nil || len(out) == 0 {
			return ""
		}
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return truncateString(line, 120)
}

func parametersForTool(id string) []toolParameter {
	common := []toolParameter{
		{Name: "timeout_seconds", Label: "Timeout", Type: "number", Default: 60, Description: "Per-tool timeout in seconds."},
		{Name: "extra_args", Label: "Extra Safe Args", Type: "list", Description: "Additional safe arguments for compatible subprocess tools."},
	}
	switch id {
	case "nmap":
		return []toolParameter{{Name: "timeout_seconds", Label: "Timeout", Type: "number", Default: 45, Description: "Per-tool timeout in seconds."}}
	case "ffuf":
		return append([]toolParameter{
			{Name: "wordlist", Label: "Wordlist", Type: "path", Description: "Content discovery wordlist path."},
			{Name: "matcher", Label: "Matcher", Type: "string", Description: "Use extra args for ffuf matchers such as -mc 200,204,301."},
		}, common...)
	case "nuclei-tech", "nuclei-vuln":
		return append([]toolParameter{{Name: "templates", Label: "Templates", Type: "path", Description: "Nuclei templates directory."}, {Name: "severity", Label: "Severity", Type: "enum", Options: []string{"info", "low", "medium", "high", "critical", "low,medium,high,critical", "medium,high,critical"}}}, common...)
	case "sqlmap":
		return append([]toolParameter{{Name: "level", Label: "Level", Type: "number", Default: 1, Description: "sqlmap level, clamped to 1-5."}, {Name: "risk", Label: "Risk", Type: "number", Default: 1, Description: "sqlmap risk, clamped to 1-3."}}, common...)
	case "dalfox":
		return append([]toolParameter{{Name: "blind", Label: "Blind Callback", Type: "string"}, {Name: "skip_grepping", Label: "Skip Grepping", Type: "boolean"}}, common...)
	case "brute-force-check":
		return []toolParameter{
			{Name: "allow_credential_validation", Label: "Allow Credential Check", Type: "boolean", Description: "Enable strict configured credential validation for explicitly safe targets."},
			{Name: "allow_brute_force", Label: "Allow Brute Force Check", Type: "boolean", Description: "Alias for allowing the benchmark brute-force validator."},
			{Name: "intentionally_vulnerable", Label: "Intentionally Vulnerable", Type: "boolean", Description: "Confirms the target is a lab or benchmark built for active validation."},
			{Name: "non_production", Label: "Non-production", Type: "boolean", Description: "Confirms the target is not a production system."},
			{Name: "max_attempts", Label: "Max Attempts", Type: "number", Default: 1, Description: "Total credential attempts, clamped to 1-3."},
		}
	case "dom-xss-check":
		return []toolParameter{
			{Name: "allow_dom_xss", Label: "Allow DOM XSS Check", Type: "boolean", Description: "Enable browser-backed DOM marker validation for explicitly safe targets."},
			{Name: "intentionally_vulnerable", Label: "Intentionally Vulnerable", Type: "boolean", Description: "Confirms the target is a lab or benchmark built for active validation."},
			{Name: "non_production", Label: "Non-production", Type: "boolean", Description: "Confirms the target is not a production system."},
			{Name: "browser_path", Label: "Browser Path", Type: "path", Description: "Optional Chrome or Chromium executable path."},
			{Name: "timeout_seconds", Label: "Timeout", Type: "number", Default: 25, Description: "Per-browser probe timeout in seconds."},
			{Name: "wait_ms", Label: "Wait", Type: "number", Default: 500, Description: "Milliseconds to wait after navigation before checking the DOM marker."},
		}
	case "command-injection-check":
		return []toolParameter{
			{Name: "allow_command_injection", Label: "Allow Command Check", Type: "boolean", Description: "Enable harmless marker command validation for explicitly safe targets."},
			{Name: "intentionally_vulnerable", Label: "Intentionally Vulnerable", Type: "boolean", Description: "Confirms the target is a lab or benchmark built for active validation."},
			{Name: "non_production", Label: "Non-production", Type: "boolean", Description: "Confirms the target is not a production system."},
		}
	case "stored-xss-check":
		return []toolParameter{
			{Name: "allow_stored_xss", Label: "Allow Stored XSS Check", Type: "boolean", Description: "Enable persistent marker validation for explicitly safe targets."},
			{Name: "intentionally_vulnerable", Label: "Intentionally Vulnerable", Type: "boolean", Description: "Confirms the target is a lab or benchmark built for active validation."},
			{Name: "non_production", Label: "Non-production", Type: "boolean", Description: "Confirms the target is not a production system."},
		}
	case "csp-review":
		return []toolParameter{
			{Name: "max_pages", Label: "Max Pages", Type: "number", Default: 10, Description: "Maximum seeded CSP-related pages to review, clamped to 25."},
		}
	default:
		return nil
	}
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
