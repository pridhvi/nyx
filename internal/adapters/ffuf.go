package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

type FFUF struct{}

func NewFFUF() FFUF {
	return FFUF{}
}

func (FFUF) ID() string { return "ffuf" }

func (FFUF) Name() string { return "ffuf" }

func (FFUF) Phase() Phase { return PhaseEnumerate }

func (FFUF) DependsOn() []string { return []string{"security-headers"} }

func (FFUF) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.IsAlive && (input.Target.Protocol == "http" || input.Target.Protocol == "https")
}

func (a FFUF) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	wordlist := commonWordlistPath()
	if configured := toolParamString(input, "wordlist"); configured != "" {
		wordlist = configured
	}
	var tempWordlist string
	routes := append(sourceValues(input.SourceFindings, models.SourceKindRoute), seededPathValues(input)...)
	if len(routes) > 0 {
		file, err := os.CreateTemp("", "nyx-routes-*.txt")
		if err == nil {
			for _, route := range routes {
				_, _ = fmt.Fprintln(file, strings.TrimPrefix(route, "/"))
			}
			_ = file.Close()
			tempWordlist = file.Name()
			wordlist = tempWordlist
			defer os.Remove(tempWordlist)
		}
	}
	baseURL := strings.TrimRight(targetBaseURL(input.Target), "/") + "/FUZZ"
	args := []string{"-u", baseURL, "-w", wordlist, "-of", "json", "-noninteractive", "-t", "5", "-rate", "25"}
	authArgs, cleanupAuth, err := authFileCommandArgs(input, a.ID(), baseURL)
	if err != nil {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), redactCommandArgs(args), "failed to prepare auth request file: "+err.Error(), 1)}, nil
	}
	defer cleanupAuth()
	if len(authArgs) > 0 {
		args = []string{"-w", wordlist, "-of", "json", "-noninteractive", "-t", "5", "-rate", "25"}
		args = append(args, authArgs...)
	}
	if matcher := toolParamString(input, "matcher"); matcher != "" {
		args = append(args, "-mc", matcher)
	}
	args = append(args, toolParamStringList(input, "extra_args")...)
	displayArgs := redactCommandArgs(args)
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), displayArgs, reason, 1)}, nil
	}
	if wordlist == "" {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), displayArgs, "no ffuf wordlist found in common system locations", 127)}, nil
	}
	run := newToolRun(input, a.ID(), displayArgs)
	result := RunCommand(ctx, commandTimeout(input, 45*time.Second), "ffuf", args...)
	findings := parseFFUFFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type ffufOutput struct {
	Results []struct {
		Input        map[string]string `json:"input"`
		Position     int               `json:"position"`
		Status       int               `json:"status"`
		Length       int               `json:"length"`
		Words        int               `json:"words"`
		Lines        int               `json:"lines"`
		URL          string            `json:"url"`
		RedirectURL  string            `json:"redirectlocation"`
		ContentType  string            `json:"content-type"`
		ResultFile   string            `json:"resultfile"`
		Host         string            `json:"host"`
		ScraperData  map[string]any    `json:"scraper"`
		Duration     int64             `json:"duration"`
		ContentWords int               `json:"content_words"`
	} `json:"results"`
}

func parseFFUFFindings(input AdapterInput, raw string) []models.Finding {
	var parsed ffufOutput
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	var findings []models.Finding
	for _, result := range parsed.Results {
		if result.URL == "" || result.Status == 404 {
			continue
		}
		severity := models.SeverityInfo
		tags := []string{"ffuf", "content-discovery"}
		title := "Discovered web path"
		if strings.Contains(strings.ToLower(result.URL), "admin") {
			severity = models.SeverityLow
			tags = append(tags, "admin-panel")
			title = "Potential administrative path discovered"
		}
		findings = append(findings, externalFinding(
			input,
			"ffuf",
			models.FindingTypeExposure,
			severity,
			title,
			fmt.Sprintf("ffuf discovered %s with HTTP status %d.", result.URL, result.Status),
			"Review whether the discovered path should be publicly accessible.",
			raw,
			map[string]any{
				"url":          result.URL,
				"status":       result.Status,
				"length":       result.Length,
				"words":        result.Words,
				"lines":        result.Lines,
				"redirect_url": result.RedirectURL,
			},
			tags,
		))
	}
	return findings
}
