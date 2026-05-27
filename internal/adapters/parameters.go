package adapters

import (
	"fmt"
	"strings"
)

func ValidateToolParameters(parameters map[string]map[string]any) error {
	for toolID, values := range parameters {
		toolID = strings.TrimSpace(toolID)
		if toolID == "" {
			return fmt.Errorf("tool parameter entry is missing a tool id")
		}
		if strings.HasPrefix(toolID, "plugin:") {
			continue
		}
		if _, ok := Get(toolID); !ok {
			return fmt.Errorf("tool parameters reference unknown tool %q", toolID)
		}
		if err := ValidateToolParameterValues(toolID, values); err != nil {
			return err
		}
	}
	return nil
}

func ValidateToolParameterValues(toolID string, values map[string]any) error {
	toolID = strings.TrimSpace(toolID)
	if toolID == "" || strings.HasPrefix(toolID, "plugin:") || len(values) == 0 {
		return nil
	}
	allowed := supportedToolParameterNames(toolID)
	for name, value := range values {
		if !allowed[name] {
			return fmt.Errorf("tool %q does not support parameter %q", toolID, name)
		}
		if name == "extra_args" {
			if err := ValidateExtraArgs(toolID, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateExtraArgs(toolID string, value any) error {
	args := parameterStringList(value)
	allowedFlags := safeExtraArgFlags(toolID)
	if len(allowedFlags) == 0 && len(args) > 0 {
		return fmt.Errorf("tool %q does not accept extra args", toolID)
	}
	for _, arg := range args {
		if len(arg) > 200 || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("tool %q extra args contain an invalid argument", toolID)
		}
		if strings.HasPrefix(arg, "-") && !allowedFlags[arg] {
			return fmt.Errorf("tool %q extra arg %q is not in the safe allow-list", toolID, arg)
		}
	}
	return nil
}

func supportedToolParameterNames(toolID string) map[string]bool {
	common := map[string]bool{
		"timeout_seconds": true,
		"extra_args":      true,
	}
	switch toolID {
	case "nmap":
		return map[string]bool{"timeout_seconds": true}
	case "ffuf":
		return mergeParameterNames(common, "wordlist", "matcher")
	case "nuclei-tech", "nuclei-vuln":
		return mergeParameterNames(common, "templates", "severity")
	case "sqlmap":
		return mergeParameterNames(common, "level", "risk")
	case "dalfox":
		return mergeParameterNames(common, "blind", "skip_grepping")
	case "command-injection-check":
		return map[string]bool{
			"enabled":                  true,
			"allow_active":             true,
			"allow_command_injection":  true,
			"intentionally_vulnerable": true,
			"non_production":           true,
		}
	case "stored-xss-check":
		return map[string]bool{
			"enabled":                  true,
			"allow_active":             true,
			"allow_stored_xss":         true,
			"intentionally_vulnerable": true,
			"non_production":           true,
		}
	default:
		return map[string]bool{}
	}
}

func mergeParameterNames(base map[string]bool, names ...string) map[string]bool {
	out := make(map[string]bool, len(base)+len(names))
	for name, ok := range base {
		out[name] = ok
	}
	for _, name := range names {
		out[name] = true
	}
	return out
}

func safeExtraArgFlags(toolID string) map[string]bool {
	flags := map[string][]string{
		"ffuf":        {"-ac", "-b", "-fc", "-fl", "-fs", "-fw", "-H", "-mc", "-rate", "-recursion", "-recursion-depth", "-t", "-timeout"},
		"nuclei-tech": {"-c", "-exclude-tags", "-headless", "-retries", "-rl", "-tags", "-timeout"},
		"nuclei-vuln": {"-c", "-exclude-tags", "-headless", "-retries", "-rl", "-tags", "-timeout"},
		"sqlmap":      {"--delay", "--param-filter", "--random-agent", "--technique", "--threads", "--timeout"},
		"dalfox":      {"--delay", "--follow-redirects", "--only-poc", "--timeout", "--worker"},
	}
	out := map[string]bool{}
	for _, flag := range flags[toolID] {
		out[flag] = true
	}
	return out
}

func parameterStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return compactParameterStrings(typed)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		return compactParameterStrings(strings.Fields(typed))
	default:
		text := strings.TrimSpace(fmt.Sprint(typed))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func compactParameterStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
