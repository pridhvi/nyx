package suppress

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pridhvi/nyx/internal/adapters"
)

type Rule = adapters.SuppressionRule

func Parse(repoRoot string) ([]Rule, error) {
	file, err := os.OpenInRoot(repoRoot, ".nyx-audit-ignore")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		rules = append(rules, Rule{ToolID: strings.TrimSpace(parts[0]), RuleID: strings.TrimSpace(parts[1]), PathGlob: strings.TrimSpace(parts[2])})
	}
	return rules, nil
}

func Matches(rules []Rule, toolID, ruleID, filePath string) bool {
	filePath = filepath.ToSlash(filePath)
	for _, rule := range rules {
		if !fieldMatches(rule.ToolID, toolID) || !fieldMatches(rule.RuleID, ruleID) {
			continue
		}
		if globMatches(rule.PathGlob, filePath) {
			return true
		}
	}
	return false
}

func fieldMatches(pattern, value string) bool {
	return pattern == "*" || pattern == "" || pattern == value
}

func globMatches(pattern, value string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	pattern = filepath.ToSlash(pattern)
	if ok, _ := filepath.Match(pattern, value); ok {
		return true
	}
	if strings.HasPrefix(pattern, "**/") {
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "**/"))
	}
	return strings.Contains(value, strings.Trim(pattern, "*"))
}
