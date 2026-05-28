package source

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type AnalysisResult struct {
	Language  string
	Framework string
	Findings  []models.SourceFinding
}

func Analyse(repoPath, sessionID string) (AnalysisResult, error) {
	extractors := []Extractor{
		PythonExtractor{},
		JavaScriptExtractor{},
		GoExtractor{},
		PHPExtractor{},
		RubyExtractor{},
		JavaExtractor{},
	}
	for _, extractor := range extractors {
		if !extractor.Detect(repoPath) {
			continue
		}
		findings, err := extractor.Extract(repoPath, sessionID)
		if err != nil {
			return AnalysisResult{}, err
		}
		return AnalysisResult{Language: extractor.Language(), Framework: extractor.Framework(), Findings: findings}, nil
	}
	return AnalysisResult{Language: "unknown", Framework: "unknown"}, fmt.Errorf("no supported language/framework detected in %s", repoPath)
}

type genericExtractor struct {
	language   string
	framework  string
	extensions []string
	markers    []string
}

func (e genericExtractor) Detect(repoPath string) bool {
	for _, marker := range e.markers {
		if _, err := os.Stat(filepath.Join(repoPath, marker)); err == nil {
			return true
		}
	}
	found := false
	_ = filepath.WalkDir(repoPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found || entry.IsDir() || isExcludedPath(path) {
			return nil
		}
		for _, ext := range e.extensions {
			if strings.EqualFold(filepath.Ext(path), ext) {
				found = true
				return nil
			}
		}
		return nil
	})
	return found
}

func (e genericExtractor) Extract(repoPath, sessionID string) ([]models.SourceFinding, error) {
	var findings []models.SourceFinding
	root, err := os.OpenRoot(repoPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	err = filepath.WalkDir(repoPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || isExcludedPath(path) || !e.matchesExt(path) {
			return nil
		}
		rel := relativePath(repoPath, path)
		body, err := readSourceFileInRoot(root, rel)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(body), "\n")
		for idx, line := range lines {
			lineNo := idx + 1
			findings = append(findings, e.matchLine(sessionID, rel, lineNo, line, contextAround(lines, idx))...)
		}
		return nil
	})
	return findings, err
}

func readSourceFileInRoot(root *os.Root, rel string) ([]byte, error) {
	rel = filepath.Clean(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("source path escapes root: %s", rel)
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
		return nil, fmt.Errorf("source path is not a regular file: %s", rel)
	}
	return io.ReadAll(file)
}

func (e genericExtractor) matchesExt(path string) bool {
	for _, ext := range e.extensions {
		if strings.EqualFold(filepath.Ext(path), ext) {
			return true
		}
	}
	return false
}

func (e genericExtractor) matchLine(sessionID, rel string, lineNo int, line, ctx string) []models.SourceFinding {
	var findings []models.SourceFinding
	add := func(kind models.SourceFindingKind, value, method, notes string) {
		value = strings.TrimSpace(value)
		if value == "" {
			value = strings.TrimSpace(line)
		}
		findings = append(findings, models.SourceFinding{
			ID:         models.NewID(),
			SessionID:  sessionID,
			Kind:       kind,
			Language:   e.language,
			Framework:  e.framework,
			FilePath:   rel,
			LineNumber: lineNo,
			Value:      value,
			Method:     strings.ToUpper(method),
			Context:    ctx,
			Notes:      notes,
			CreatedAt:  time.Now().UTC(),
		})
	}
	for _, route := range routePatterns[e.language] {
		if match := route.re.FindStringSubmatch(line); len(match) > 0 {
			add(models.SourceKindRoute, group(match, route.valueGroup), group(match, route.methodGroup), "")
		}
	}
	for _, pattern := range parameterPatterns[e.language] {
		if match := pattern.FindStringSubmatch(line); len(match) > 1 {
			add(models.SourceKindParameter, match[1], "", "")
		}
	}
	if sqlSinkPattern.MatchString(line) {
		add(models.SourceKindSQLSink, line, "", "")
	}
	if fileUploadPattern.MatchString(line) {
		add(models.SourceKindFileUpload, line, "", "")
	}
	if authPattern.MatchString(line) {
		add(models.SourceKindAuthMiddleware, line, "", "")
	}
	if secretPattern.MatchString(line) {
		add(models.SourceKindSecret, line, "", "")
	}
	if ssrfPattern.MatchString(line) {
		add(models.SourceKindSSRFSink, line, "", "")
	}
	if deserialisePattern.MatchString(line) {
		add(models.SourceKindDeserialisationSink, line, "", "")
	}
	if looksUnprotectedRoute(line, e.language) {
		add(models.SourceKindUnprotectedRoute, line, "", "Low confidence - middleware may be applied at a higher scope")
	}
	return findings
}

type routePattern struct {
	re          *regexp.Regexp
	valueGroup  int
	methodGroup int
}

var routePatterns = map[string][]routePattern{
	"python": {
		{regexp.MustCompile(`@(?:app|router)\.(get|post|put|delete|patch|route)\(\s*["']([^"']+)`), 2, 1},
		{regexp.MustCompile(`path\(\s*["']([^"']+)`), 1, 0},
	},
	"javascript": {
		{regexp.MustCompile(`(?:app|router)\.(get|post|put|delete|patch|use)\(\s*["']([^"']+)`), 2, 1},
	},
	"go": {
		{regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH)\(\s*["']([^"']+)`), 2, 1},
		{regexp.MustCompile(`HandleFunc\(\s*["']([^"']+)`), 1, 0},
	},
	"php": {
		{regexp.MustCompile(`Route::(get|post|put|delete|patch)\(\s*["']([^"']+)`), 2, 1},
	},
	"ruby": {
		{regexp.MustCompile(`\b(get|post|put|delete|patch)\s+["']([^"']+)`), 2, 1},
	},
	"java": {
		{regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?["']([^"']+)`), 2, 1},
	},
}

var parameterPatterns = map[string][]*regexp.Regexp{
	"python":     {regexp.MustCompile(`request\.(?:args|form|GET|POST)\.get\(\s*["']([^"']+)`)},
	"javascript": {regexp.MustCompile(`req\.(?:query|body|params)\.([A-Za-z_][A-Za-z0-9_]*)`)},
	"go":         {regexp.MustCompile(`(?:Query|Param)\(\s*["']([^"']+)`), regexp.MustCompile(`Query\(\)\.Get\(\s*["']([^"']+)`)},
	"php":        {regexp.MustCompile(`\$_(?:GET|POST|REQUEST)\[['"]([^'"]+)`)},
	"ruby":       {regexp.MustCompile(`params\[[':]?([A-Za-z_][A-Za-z0-9_]*)`)},
	"java":       {regexp.MustCompile(`@RequestParam\(\s*["']([^"']+)`)},
}

var (
	sqlSinkPattern     = regexp.MustCompile(`(?i)(raw\(|\.Raw\(|text\(|SELECT .*\+|WHERE .*\+|query\([^)]*\+)`)
	fileUploadPattern  = regexp.MustCompile(`(?i)(request\.FILES|multer|upload\.single|move_uploaded_file|multipart\.Form|MultipartFile)`)
	authPattern        = regexp.MustCompile(`(?i)(auth|login_required|permission|authenticate|authorize|jwt|session)`)
	secretPattern      = regexp.MustCompile(`(?i)(AKIA[A-Z0-9]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|password\s*=|secret\s*=|api[_-]?key\s*=)`)
	ssrfPattern        = regexp.MustCompile(`(?i)(requests\.(get|post)\(|http\.Get\(|fetch\(|Net::HTTP|curl_exec)`)
	deserialisePattern = regexp.MustCompile(`(?i)(pickle\.loads|yaml\.load|unserialize\(|ObjectInputStream|readObject\()`)
	testPathPattern    = regexp.MustCompile(`(?i)(^|/)(__tests__|tests?|fixtures?)(/|$)|(_test\.go|test_.*\.py|\.spec\.[jt]sx?$)`)
)

func looksUnprotectedRoute(line, language string) bool {
	for _, route := range routePatterns[language] {
		if route.re.MatchString(line) && !authPattern.MatchString(line) {
			return true
		}
	}
	return false
}

func isExcludedPath(path string) bool {
	return testPathPattern.MatchString(filepath.ToSlash(path))
}

func relativePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func contextAround(lines []string, idx int) string {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 6
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func group(match []string, idx int) string {
	if idx <= 0 || idx >= len(match) {
		return ""
	}
	return match[idx]
}
