package adapters

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
	"github.com/pridhvi/nyx/internal/source"
)

func init() {
	for _, adapter := range []StaticAdapter{
		newCommandStaticAdapter("semgrep", "Semgrep", []string{"any"}, "semgrep", func(input StaticAdapterInput) []string {
			return []string{"scan", "--json", "--config", "p/security-audit", "--config", "p/secrets", "--config", "p/owasp-top-ten", input.RepoPath}
		}),
		newCommandStaticAdapter("bandit", "Bandit", []string{"python"}, "bandit", func(input StaticAdapterInput) []string {
			return []string{"-r", input.RepoPath, "-f", "json", "--severity-level", "low", "--confidence-level", "low"}
		}),
		newCommandStaticAdapter("gosec", "gosec", []string{"go"}, "gosec", func(input StaticAdapterInput) []string {
			return []string{"-fmt", "json", filepath.Join(input.RepoPath, "...")}
		}),
		newCommandStaticAdapter("govulncheck", "govulncheck", []string{"go"}, "govulncheck", func(input StaticAdapterInput) []string {
			return []string{"-json", input.RepoPath}
		}),
		newCommandStaticAdapter("npm-audit", "npm audit", []string{"javascript"}, "npm", func(input StaticAdapterInput) []string {
			return []string{"audit", "--json", "--prefix", input.RepoPath}
		}),
		newCommandStaticAdapter("retirejs", "retire.js", []string{"javascript"}, "retire", func(input StaticAdapterInput) []string {
			return []string{"--js", "--node", "--outputformat", "json", "--path", input.RepoPath}
		}),
		newCommandStaticAdapter("safety", "Safety", []string{"python"}, "safety", func(input StaticAdapterInput) []string {
			return []string{"check", "--json", "-r", filepath.Join(input.RepoPath, "requirements.txt")}
		}),
		newCommandStaticAdapter("brakeman", "Brakeman", []string{"ruby"}, "brakeman", func(input StaticAdapterInput) []string {
			return []string{"-f", "json", "-q", input.RepoPath}
		}),
		newCommandStaticAdapter("spotbugs", "SpotBugs", []string{"java"}, "spotbugs", func(input StaticAdapterInput) []string {
			return []string{"-textui", "-xml", input.RepoPath}
		}),
		newCommandStaticAdapter("psalm", "Psalm", []string{"php"}, "psalm", func(input StaticAdapterInput) []string {
			return []string{"--output-format=json", input.RepoPath}
		}),
		newCommandStaticAdapter("trufflehog", "TruffleHog", []string{"any"}, "trufflehog", func(input StaticAdapterInput) []string {
			return []string{"filesystem", input.RepoPath, "--json", "--no-update"}
		}),
		newCommandStaticAdapter("gitleaks", "gitleaks", []string{"any"}, "gitleaks", func(input StaticAdapterInput) []string {
			return []string{"detect", "--source", input.RepoPath, "--report-format", "json", "--no-git"}
		}),
		newCommandStaticAdapter("grype", "Grype", []string{"any"}, "grype", func(input StaticAdapterInput) []string {
			return []string{input.RepoPath, "-o", "json"}
		}),
		javaPatternStaticAdapter{},
		sourceStaticAdapter{id: "authmiddleware", name: "Auth middleware gap", kind: models.SourceKindUnprotectedRoute, severity: models.SeverityMedium},
		sourceStaticAdapter{id: "idor", name: "IDOR pattern detection", kind: models.SourceKindParameter, severity: models.SeverityMedium},
		sourceStaticAdapter{id: "dangerfuncs", name: "Dangerous function tracer", kind: models.SourceKindDeserialisationSink, severity: models.SeverityHigh},
		sourceStaticAdapter{id: "depconfusion", name: "Dependency confusion", kind: models.SourceKindSecret, severity: models.SeverityHigh},
	} {
		RegisterStatic(adapter)
	}
}

type commandStaticAdapter struct {
	id        string
	name      string
	languages []string
	binary    string
	args      func(StaticAdapterInput) []string
}

func newCommandStaticAdapter(id, name string, languages []string, binary string, args func(StaticAdapterInput) []string) commandStaticAdapter {
	return commandStaticAdapter{id: id, name: name, languages: languages, binary: binary, args: args}
}

func (a commandStaticAdapter) ID() string          { return a.id }
func (a commandStaticAdapter) Name() string        { return a.name }
func (a commandStaticAdapter) Languages() []string { return a.languages }
func (a commandStaticAdapter) Available() bool {
	_, err := exec.LookPath(a.binary)
	return err == nil
}
func (a commandStaticAdapter) Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error) {
	run := models.ToolRun{ID: models.NewID(), SessionID: input.SessionID, ToolID: a.id, Args: append([]string{a.binary}, a.args(input)...), StartedAt: time.Now().UTC()}
	result := RunCommand(ctx, 3*time.Minute, a.binary, a.args(input)...)
	run.RawStdout = result.Stdout
	run.RawStderr = result.Stderr
	run.ExitCode = result.ExitCode
	run.DurationMS = result.DurationMS
	now := time.Now().UTC()
	run.NormalizedAt = &now
	findings, cves := parseStaticOutput(input, a.id, result.Stdout)
	run.FindingCount = len(findings)
	return StaticAdapterOutput{Findings: findings, CVEs: cves, ToolRun: run}, nil
}

type javaPatternStaticAdapter struct{}

func (javaPatternStaticAdapter) ID() string          { return "javapatterns" }
func (javaPatternStaticAdapter) Name() string        { return "Java dangerous pattern audit" }
func (javaPatternStaticAdapter) Languages() []string { return []string{"java"} }
func (javaPatternStaticAdapter) Available() bool     { return true }

func (a javaPatternStaticAdapter) Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error) {
	started := time.Now().UTC()
	findings, err := scanJavaPatternFindings(ctx, input)
	now := time.Now().UTC()
	return StaticAdapterOutput{Findings: findings, ToolRun: models.ToolRun{
		ID:           models.NewID(),
		SessionID:    input.SessionID,
		ToolID:       a.ID(),
		Args:         []string{a.ID(), input.RepoPath},
		ExitCode:     exitCodeForErr(err),
		DurationMS:   time.Since(started).Milliseconds(),
		FindingCount: len(findings),
		RawStdout:    fmt.Sprintf("scanned Java source patterns; findings=%d\n", len(findings)),
		RawStderr:    errorString(err),
		NormalizedAt: &now,
		StartedAt:    started,
	}}, err
}

type sourceStaticAdapter struct {
	id       string
	name     string
	kind     models.SourceFindingKind
	severity models.Severity
}

func (a sourceStaticAdapter) ID() string          { return a.id }
func (a sourceStaticAdapter) Name() string        { return a.name }
func (a sourceStaticAdapter) Languages() []string { return []string{"any"} }
func (a sourceStaticAdapter) Available() bool     { return true }
func (a sourceStaticAdapter) Run(ctx context.Context, input StaticAdapterInput) (StaticAdapterOutput, error) {
	started := time.Now().UTC()
	result, _ := source.Analyse(input.RepoPath, input.SessionID)
	var findings []models.Finding
	for _, sourceFinding := range result.Findings {
		if sourceFinding.Kind != a.kind {
			continue
		}
		findings = append(findings, sourceFindingToAuditFinding(input.SessionID, a.id, a.severity, sourceFinding))
	}
	now := time.Now().UTC()
	return StaticAdapterOutput{Findings: findings, ToolRun: models.ToolRun{
		ID:           models.NewID(),
		SessionID:    input.SessionID,
		ToolID:       a.id,
		Args:         []string{a.id, input.RepoPath},
		ExitCode:     0,
		DurationMS:   time.Since(started).Milliseconds(),
		FindingCount: len(findings),
		NormalizedAt: &now,
		StartedAt:    started,
	}}, ctx.Err()
}

func parseStaticOutput(input StaticAdapterInput, toolID, raw string) ([]models.Finding, []models.CVEMatch) {
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		if toolID == "spotbugs" {
			return parseSpotBugsXML(input, toolID, raw), nil
		}
		return nil, nil
	}
	switch toolID {
	case "semgrep":
		return parseSemgrep(input, decoded), nil
	case "bandit":
		return parseBandit(input, decoded), nil
	case "gosec":
		return parseGosec(input, decoded), nil
	case "govulncheck":
		return nil, parseGovulncheck(input, decoded, toolID)
	case "npm-audit":
		return nil, parseNPMAudit(input, decoded, toolID)
	case "retirejs":
		return parseRetireJS(input, decoded), parseRetireJSCVEs(input, decoded, toolID)
	case "safety":
		return nil, parseSafety(input, decoded, toolID)
	case "brakeman":
		return parseBrakeman(input, decoded), nil
	case "psalm":
		return parsePsalm(input, decoded), nil
	case "trufflehog":
		return parseSecrets(input, decoded, toolID), nil
	case "gitleaks":
		return parseSecrets(input, decoded, toolID), nil
	case "grype":
		return nil, parseGrype(input, decoded, toolID)
	}
	return parseGenericStaticOutput(input, toolID, decoded)
}

func parseGenericStaticOutput(input StaticAdapterInput, toolID string, decoded any) ([]models.Finding, []models.CVEMatch) {
	var findings []models.Finding
	var cves []models.CVEMatch
	walkStaticJSON(decoded, func(obj map[string]any) {
		cveID := firstString(obj, "cve", "CVE", "id", "cve_id")
		if strings.HasPrefix(strings.ToUpper(cveID), "CVE-") || strings.HasPrefix(strings.ToUpper(cveID), "GHSA-") {
			cves = append(cves, models.CVEMatch{
				ID:              models.NewID(),
				SessionID:       input.SessionID,
				CVEID:           cveID,
				CVSSv3Score:     numberValue(obj, "cvss", "cvss_score", "score"),
				Description:     firstString(obj, "title", "summary", "description", "message"),
				PackageName:     firstString(obj, "package", "module", "name", "dependency"),
				PackageVersion:  firstString(obj, "version", "installed_version", "current_version"),
				AffectedVersion: firstString(obj, "affected_version", "installed_version", "version"),
				FixedVersion:    firstString(obj, "fixed_version", "fixed", "fix"),
				Source:          "audit/" + toolID,
				ConfidenceScore: 0.6,
			})
			return
		}
		file := firstString(obj, "path", "file", "filename", "component", "location")
		message := firstString(obj, "message", "issue_text", "details", "description", "check_id", "rule_id")
		if file == "" || message == "" || sourceFileExcluded(file) || !diffAllows(input.DiffPaths, file) {
			return
		}
		line := int(numberValue(obj, "line", "line_number", "start_line"))
		findings = append(findings, models.Finding{
			ID:          models.NewID(),
			SessionID:   input.SessionID,
			ToolID:      "audit/" + toolID,
			Type:        models.FindingTypeVulnerability,
			Severity:    severityFromString(firstString(obj, "severity", "issue_severity", "level")),
			Confidence:  0.5,
			Title:       message,
			Description: message,
			URL:         fileURL(file, line),
			EvidenceRaw: mustJSON(obj),
			CodeContext: firstString(obj, "code", "context", "extra"),
			Status:      models.FindingStatusOpen,
			Tags:        []string{"audit", toolID},
			CreatedAt:   time.Now().UTC(),
		})
	})
	return findings, cves
}

func parseSemgrep(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	for _, obj := range arrayAt(decoded, "results") {
		path := firstString(obj, "path")
		extra := mapAt(obj, "extra")
		message := firstString(extra, "message", "metadata")
		if message == "" {
			message = firstString(obj, "check_id")
		}
		line := int(numberValue(mapAt(obj, "start"), "line"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, "semgrep", path, line, message, severityFromString(firstString(extra, "severity")), obj))
	}
	return findings
}

func parseBandit(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	for _, obj := range arrayAt(decoded, "results") {
		path := firstString(obj, "filename")
		message := firstString(obj, "issue_text", "test_name", "test_id")
		line := int(numberValue(obj, "line_number"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, "bandit", path, line, message, severityFromString(firstString(obj, "issue_severity")), obj))
	}
	return findings
}

func parseGosec(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	for _, obj := range arrayAt(decoded, "Issues") {
		path := firstString(obj, "file")
		message := firstString(obj, "details", "rule_id")
		line := int(numberValue(obj, "line"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, "gosec", path, line, message, severityFromString(firstString(obj, "severity")), obj))
	}
	return findings
}

func parseBrakeman(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	for _, obj := range arrayAt(decoded, "warnings") {
		path := firstString(obj, "file")
		message := firstString(obj, "message", "warning_type")
		line := int(numberValue(obj, "line"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, "brakeman", path, line, message, confidenceSeverity(numberValue(obj, "confidence")), obj))
	}
	return findings
}

func parsePsalm(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	for _, obj := range anyArray(decoded) {
		path := firstString(obj, "file_path", "file_name")
		message := firstString(obj, "message", "type")
		line := int(numberValue(obj, "line_from", "line"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, "psalm", path, line, message, severityFromString(firstString(obj, "severity")), obj))
	}
	return findings
}

func parseRetireJS(input StaticAdapterInput, decoded any) []models.Finding {
	var findings []models.Finding
	walkStaticJSON(decoded, func(obj map[string]any) {
		path := firstString(obj, "file", "fileName", "path")
		message := firstString(obj, "component", "module", "name")
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			return
		}
		findings = append(findings, staticFinding(input, "retirejs", path, int(numberValue(obj, "line")), "vulnerable component "+message, models.SeverityMedium, obj))
	})
	return findings
}

func parseSecrets(input StaticAdapterInput, decoded any, toolID string) []models.Finding {
	var findings []models.Finding
	walkStaticJSON(decoded, func(obj map[string]any) {
		path := firstString(obj, "SourceMetadata", "path", "file", "File", "filename")
		if nested := mapAt(mapAt(obj, "SourceMetadata"), "Data"); nested != nil {
			path = firstStaticNonEmpty(firstString(mapAt(nested, "Filesystem"), "file", "path"), firstString(mapAt(nested, "Git"), "file", "path"), path)
		}
		message := firstString(obj, "DetectorName", "Description", "RuleID", "rule", "description")
		line := int(numberValue(obj, "StartLine", "line"))
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			return
		}
		findings = append(findings, staticFinding(input, toolID, path, line, "secret detected: "+message, models.SeverityHigh, obj))
	})
	return findings
}

func parseSpotBugsXML(input StaticAdapterInput, toolID, raw string) []models.Finding {
	var report struct {
		Bugs []struct {
			Type     string `xml:"type,attr"`
			Category string `xml:"category,attr"`
			Priority string `xml:"priority,attr"`
			Long     string `xml:"LongMessage"`
			Source   struct {
				Path  string `xml:"sourcepath,attr"`
				Start int    `xml:"start,attr"`
			} `xml:"SourceLine"`
		} `xml:"BugInstance"`
	}
	if err := xml.Unmarshal([]byte(raw), &report); err != nil {
		return nil
	}
	var findings []models.Finding
	for _, bug := range report.Bugs {
		path := bug.Source.Path
		message := firstStaticNonEmpty(bug.Long, bug.Type, bug.Category)
		if path == "" || message == "" || sourceFileExcluded(path) || !diffAllows(input.DiffPaths, path) {
			continue
		}
		findings = append(findings, staticFinding(input, toolID, path, bug.Source.Start, message, spotbugsSeverity(bug.Priority), bug))
	}
	return findings
}

func parseGovulncheck(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	var cves []models.CVEMatch
	walkStaticJSON(decoded, func(obj map[string]any) {
		osv := mapAt(obj, "osv")
		id := firstString(osv, "id")
		if id == "" {
			id = firstString(obj, "id")
		}
		if id == "" {
			return
		}
		cves = append(cves, cveMatch(input, toolID, id, firstString(osv, "summary", "details"), firstString(obj, "module", "package"), firstString(obj, "version"), obj))
	})
	return cves
}

func parseNPMAudit(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	var cves []models.CVEMatch
	if vulns := mapAtAny(decoded, "vulnerabilities"); vulns != nil {
		for name, value := range vulns {
			obj, ok := value.(map[string]any)
			if !ok {
				continue
			}
			for _, via := range objArray(obj["via"]) {
				id := firstCVE(firstString(via, "source", "url", "name", "cve"))
				if id == "" {
					continue
				}
				version := firstString(obj, "range", "version")
				cves = append(cves, cveMatch(input, toolID, id, firstString(via, "title", "name"), name, version, via))
			}
		}
		return cves
	}
	return parseGenericCVEs(input, decoded, toolID)
}

func parseRetireJSCVEs(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	return parseGenericCVEs(input, decoded, toolID)
}

func parseSafety(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	return parseGenericCVEs(input, decoded, toolID)
}

func parseGrype(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	var cves []models.CVEMatch
	for _, obj := range arrayAt(decoded, "matches") {
		vuln := mapAt(obj, "vulnerability")
		artifact := mapAt(obj, "artifact")
		id := firstString(vuln, "id")
		if id == "" {
			continue
		}
		match := cveMatch(input, toolID, id, firstString(vuln, "description"), firstString(artifact, "name"), firstString(artifact, "version"), obj)
		match.FixedVersion = fixedVersion(vuln)
		match.CVSSv3Score = cvssFromObject(vuln)
		cves = append(cves, match)
	}
	return cves
}

func parseGenericCVEs(input StaticAdapterInput, decoded any, toolID string) []models.CVEMatch {
	var cves []models.CVEMatch
	walkStaticJSON(decoded, func(obj map[string]any) {
		id := firstCVE(firstString(obj, "cve", "CVE", "id", "cve_id", "vulnerability_id", "advisory"))
		if id == "" {
			return
		}
		cves = append(cves, cveMatch(input, toolID, id, firstString(obj, "title", "summary", "description", "message"), firstString(obj, "package", "module", "name", "dependency"), firstString(obj, "version", "installed_version", "current_version"), obj))
	})
	return cves
}

type javaPatternClass struct {
	ID          string
	Title       string
	Description string
	Remediation string
	Severity    models.Severity
	Matches     func(line, context string) bool
}

var javaPatternClasses = []javaPatternClass{
	{ID: "cmdi", Title: "Java command execution sink", Description: "Java source contains command execution APIs that should be reviewed for untrusted input flow.", Remediation: "Avoid shelling out with untrusted data. Prefer safe library APIs, strict allow-lists, fixed argv templates, and server-side authorization checks.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "runtime.getruntime().exec", "new processbuilder", "processbuilder(")
	}},
	{ID: "sqli", Title: "Java SQL execution sink", Description: "Java source constructs or executes SQL in a way that should be reviewed for injection-safe parameter binding.", Remediation: "Use prepared statements with bound parameters for all untrusted values and avoid string-concatenated SQL.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "executequery(", "executeupdate(", "preparecall(", "createstatement(") && javaContainsAny(context, "sql", "getparameter", "getheader", "param")
	}},
	{ID: "xss", Title: "Java response output sink", Description: "Java source writes response content near request-controlled data and should be reviewed for output encoding.", Remediation: "Encode untrusted output for the browser context, prefer templating auto-escape, and validate or reject dangerous input.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "response.getwriter().print", "response.getwriter().write", "out.print") && javaContainsAny(context, "getparameter", "getheader", "urldecoder", "param")
	}},
	{ID: "pathtraver", Title: "Java file path sink", Description: "Java source performs file access near request-controlled data and should be reviewed for path traversal risk.", Remediation: "Resolve paths under a fixed root, reject traversal segments after canonicalization, and avoid direct use of request-controlled filenames.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "fileinputstream", "fileoutputstream", "randomaccessfile", "new java.io.file", "new file(") && javaContainsAny(context, "getparameter", "getheader", "getcookies", "urldecoder", "cookie")
	}},
	{ID: "crypto", Title: "Java cryptographic algorithm selection", Description: "Java source selects a cipher algorithm that should be reviewed for weak modes, deprecated algorithms, or untrusted selection.", Remediation: "Use modern authenticated encryption such as AES-GCM with fixed approved algorithms and avoid request-controlled algorithm names.", Severity: models.SeverityMedium, Matches: func(line, context string) bool {
		return javaContainsAny(line, "cipher.getinstance(")
	}},
	{ID: "hash", Title: "Java message digest usage", Description: "Java source creates a message digest and should be reviewed for weak hashing or password-storage misuse.", Remediation: "Use SHA-256 or stronger for integrity, and use password-specific KDFs such as Argon2id, bcrypt, scrypt, or PBKDF2 for passwords.", Severity: models.SeverityMedium, Matches: func(line, context string) bool {
		return javaContainsAny(line, "messagedigest.getinstance(")
	}},
	{ID: "weakrand", Title: "Java predictable randomness", Description: "Java source uses non-cryptographic randomness where security-sensitive token or key generation may require stronger entropy.", Remediation: "Use SecureRandom for security-sensitive identifiers, keys, nonces, and tokens.", Severity: models.SeverityMedium, Matches: func(line, context string) bool {
		return javaContainsAny(line, "java.util.random", "new random(", "math.random(", ".nextfloat(", ".nextint(") && !javaContainsAny(context, "securerandom")
	}},
	{ID: "securecookie", Title: "Java cookie missing secure flag", Description: "Java source creates or configures cookies in a way that should be reviewed for missing Secure attributes.", Remediation: "Set Secure, HttpOnly, and SameSite attributes on sensitive cookies and serve them only over HTTPS.", Severity: models.SeverityMedium, Matches: func(line, context string) bool {
		if javaContainsAny(line, "setsecure(false)") {
			return true
		}
		return javaContainsAny(line, "new javax.servlet.http.cookie", "new cookie(") && !javaContainsAny(context, "setsecure(true)")
	}},
	{ID: "trustbound", Title: "Java trust-boundary session write", Description: "Java source writes request-derived data into server-side session state and should be reviewed for trust-boundary violations.", Remediation: "Validate and canonicalize data before storing it in trusted session state, and avoid using user-controlled values as authorization decisions.", Severity: models.SeverityMedium, Matches: func(line, context string) bool {
		return javaContainsAny(line, "getsession().setattribute", ".setattribute(") && javaContainsAny(context, "getparameter", "getheader", "getcookies", "urldecoder", "param")
	}},
	{ID: "ldapi", Title: "Java LDAP query sink", Description: "Java source performs LDAP lookup/search operations near request-controlled data and should be reviewed for LDAP injection.", Remediation: "Escape LDAP filter values, use safe directory APIs, and restrict query templates to server-defined structures.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "dircontext", "initialdircontext", ".search(", "searchcontrols") && javaContainsAny(context, "getparameter", "getheader", "param")
	}},
	{ID: "xpathi", Title: "Java XPath evaluation sink", Description: "Java source evaluates XPath expressions near request-controlled data and should be reviewed for XPath injection.", Remediation: "Avoid string-built XPath expressions with untrusted data. Use allow-lists, fixed expressions, and safe variable binding where available.", Severity: models.SeverityHigh, Matches: func(line, context string) bool {
		return javaContainsAny(line, "xpath", ".evaluate(") && javaContainsAny(context, "getparameter", "getheader", "param")
	}},
}

func scanJavaPatternFindings(ctx context.Context, input StaticAdapterInput) ([]models.Finding, error) {
	var findings []models.Finding
	root, err := os.OpenRoot(input.RepoPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	err = filepath.WalkDir(input.RepoPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.EqualFold(filepath.Ext(path), ".java") || javaStaticExcluded(path) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(input.RepoPath, path)
		if err != nil {
			return nil
		}
		body, err := readJavaPatternFileInRoot(root, rel)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(body), "\n")
		seenInFile := map[string]bool{}
		for idx, line := range lines {
			context := javaContext(lines, idx)
			for _, class := range javaPatternClasses {
				if seenInFile[class.ID] || !class.Matches(line, context) {
					continue
				}
				seenInFile[class.ID] = true
				findings = append(findings, javaPatternFinding(input, class, filepath.ToSlash(rel), idx+1, line, context))
			}
		}
		return nil
	})
	return findings, err
}

func readJavaPatternFileInRoot(root *os.Root, rel string) ([]byte, error) {
	rel = filepath.Clean(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("java source path escapes root: %s", rel)
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("java source path is not a regular file: %s", rel)
	}
	return io.ReadAll(file)
}

func javaPatternFinding(input StaticAdapterInput, class javaPatternClass, path string, line int, evidenceLine, context string) models.Finding {
	return models.Finding{
		ID:                 models.NewID(),
		SessionID:          input.SessionID,
		ToolID:             "audit/javapatterns",
		Type:               models.FindingTypeVulnerability,
		Severity:           class.Severity,
		Confidence:         0.58,
		Title:              class.Title,
		Description:        class.Description,
		Remediation:        class.Remediation,
		URL:                fileURL(path, line),
		EvidenceRaw:        strings.TrimSpace(evidenceLine),
		EvidenceNormalized: fmt.Sprintf("java-pattern-category=%s", class.ID),
		CodeContext:        context,
		Status:             models.FindingStatusOpen,
		Tags:               []string{"audit", "javapatterns", "java", class.ID},
		CreatedAt:          time.Now().UTC(),
	}
}

func javaContext(lines []string, idx int) string {
	start := idx - 8
	if start < 0 {
		start = 0
	}
	end := idx + 9
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func javaContainsAny(value string, needles ...string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func javaStaticExcluded(path string) bool {
	normalized := filepath.ToSlash(path)
	return strings.Contains(normalized, "/target/") || strings.Contains(normalized, "/test/") || strings.Contains(normalized, "/tests/")
}

func exitCodeForErr(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func staticFinding(input StaticAdapterInput, toolID, path string, line int, message string, severity models.Severity, raw any) models.Finding {
	return models.Finding{
		ID:          models.NewID(),
		SessionID:   input.SessionID,
		ToolID:      "audit/" + toolID,
		Type:        models.FindingTypeVulnerability,
		Severity:    severity,
		Confidence:  0.5,
		Title:       message,
		Description: message,
		URL:         fileURL(path, line),
		EvidenceRaw: mustJSON(raw),
		CodeContext: firstString(mapFromAny(raw), "code", "context", "extra"),
		Status:      models.FindingStatusOpen,
		Tags:        []string{"audit", toolID},
		CreatedAt:   time.Now().UTC(),
	}
}

func cveMatch(input StaticAdapterInput, toolID, id, description, packageName, version string, raw any) models.CVEMatch {
	return models.CVEMatch{
		ID:              models.NewID(),
		SessionID:       input.SessionID,
		CVEID:           id,
		CVSSv3Score:     numberValue(mapFromAny(raw), "cvss", "cvss_score", "score"),
		Description:     description,
		PackageName:     packageName,
		PackageVersion:  version,
		AffectedVersion: firstString(mapFromAny(raw), "affected_version", "installed_version", "version", "range"),
		FixedVersion:    firstString(mapFromAny(raw), "fixed_version", "fixed", "fix"),
		References:      stringArray(mapFromAny(raw), "references", "urls"),
		Source:          "audit/" + toolID,
		ConfidenceScore: 0.65,
	}
}

func sourceFindingToAuditFinding(sessionID, toolID string, severity models.Severity, sf models.SourceFinding) models.Finding {
	return models.Finding{
		ID:          models.NewID(),
		SessionID:   sessionID,
		ToolID:      "audit/" + toolID,
		Type:        models.FindingTypeVulnerability,
		Severity:    severity,
		Confidence:  0.45,
		Title:       fmt.Sprintf("%s detected in source", strings.ReplaceAll(string(sf.Kind), "_", " ")),
		Description: sf.Notes,
		URL:         fileURL(sf.FilePath, sf.LineNumber),
		Method:      sf.Method,
		EvidenceRaw: sf.Value,
		CodeContext: sf.Context,
		Status:      models.FindingStatusOpen,
		Tags:        []string{"audit", toolID, string(sf.Kind)},
		CreatedAt:   time.Now().UTC(),
	}
}

func walkStaticJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			walkStaticJSON(item, visit)
		}
	case map[string]any:
		visit(typed)
		for _, item := range typed {
			walkStaticJSON(item, visit)
		}
	}
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := obj[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case map[string]any:
				if nested := firstString(typed, keys...); nested != "" {
					return nested
				}
			}
		}
	}
	return ""
}

func numberValue(obj map[string]any, keys ...string) float64 {
	for _, key := range keys {
		switch typed := obj[key].(type) {
		case float64:
			return typed
		case int:
			return float64(typed)
		case json.Number:
			value, _ := typed.Float64()
			return value
		case string:
			value, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
			return value
		}
	}
	return 0
}

func mapAt(obj map[string]any, key string) map[string]any {
	if obj == nil {
		return nil
	}
	if nested, ok := obj[key].(map[string]any); ok {
		return nested
	}
	return nil
}

func mapAtAny(value any, key string) map[string]any {
	return mapAt(mapFromAny(value), key)
}

func mapFromAny(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func arrayAt(value any, key string) []map[string]any {
	return objArray(mapFromAny(value)[key])
}

func anyArray(value any) []map[string]any {
	return objArray(value)
}

func objArray(value any) []map[string]any {
	var out []map[string]any
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, obj)
			}
		}
	case []map[string]any:
		out = append(out, typed...)
	case map[string]any:
		out = append(out, typed)
	}
	return out
}

func stringArray(obj map[string]any, keys ...string) []string {
	for _, key := range keys {
		switch typed := obj[key].(type) {
		case []any:
			var out []string
			for _, item := range typed {
				if value := strings.TrimSpace(fmt.Sprint(item)); value != "" {
					out = append(out, value)
				}
			}
			return out
		case []string:
			return typed
		case string:
			if strings.TrimSpace(typed) != "" {
				return []string{strings.TrimSpace(typed)}
			}
		}
	}
	return nil
}

func firstStaticNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstCVE(value string) string {
	upper := strings.ToUpper(value)
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		if idx := strings.Index(upper, prefix); idx >= 0 {
			id := upper[idx:]
			for end, ch := range id {
				if !(ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
					return strings.Trim(id[:end], ".,);]")
				}
			}
			return strings.Trim(id, ".,);]")
		}
	}
	return ""
}

func fixedVersion(obj map[string]any) string {
	if fix := mapAt(obj, "fix"); fix != nil {
		if versions := stringArray(fix, "versions"); len(versions) > 0 {
			return versions[0]
		}
	}
	for _, fix := range objArray(obj["fix"]) {
		if version := firstString(fix, "version"); version != "" {
			return version
		}
	}
	for _, fix := range objArray(obj["fixes"]) {
		if version := firstString(fix, "version"); version != "" {
			return version
		}
	}
	return firstString(obj, "fixed", "fixed_version")
}

func cvssFromObject(obj map[string]any) float64 {
	if score := numberValue(obj, "cvss", "cvss_score", "score"); score > 0 {
		return score
	}
	for _, metric := range objArray(obj["cvss"]) {
		if score := numberValue(metric, "baseScore", "score"); score > 0 {
			return score
		}
	}
	return 0
}

func confidenceSeverity(value float64) models.Severity {
	switch {
	case value <= 1:
		return models.SeverityHigh
	case value == 2:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func spotbugsSeverity(priority string) models.Severity {
	switch strings.TrimSpace(priority) {
	case "1":
		return models.SeverityHigh
	case "2":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func severityFromString(value string) models.Severity {
	switch strings.ToLower(value) {
	case "critical":
		return models.SeverityCritical
	case "error", "high":
		return models.SeverityHigh
	case "warning", "medium":
		return models.SeverityMedium
	case "low", "note", "info":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func fileURL(path string, line int) string {
	escaped := (&url.URL{Path: filepath.ToSlash(path)}).String()
	if line > 0 {
		return "file://" + escaped + fmt.Sprintf("#L%d", line)
	}
	return "file://" + escaped
}

func mustJSON(value any) string {
	body, _ := json.Marshal(value)
	return string(body)
}

func sourceFileExcluded(path string) bool {
	path = filepath.ToSlash(path)
	excluded := []string{"/__tests__/", "/test/", "/tests/", "/fixtures/", "_test.go", ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx"}
	for _, marker := range excluded {
		if strings.Contains(path, marker) || strings.HasPrefix(filepath.Base(path), "test_") {
			return true
		}
	}
	return false
}

func diffAllows(diffPaths []string, file string) bool {
	if len(diffPaths) == 0 {
		return true
	}
	file = filepath.ToSlash(file)
	for _, diffPath := range diffPaths {
		if file == filepath.ToSlash(diffPath) || strings.HasSuffix(file, filepath.ToSlash(diffPath)) {
			return true
		}
	}
	return false
}
