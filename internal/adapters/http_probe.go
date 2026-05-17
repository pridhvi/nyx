package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type HTTPProbe struct{}

func NewHTTPProbe() HTTPProbe {
	return HTTPProbe{}
}

func (HTTPProbe) ID() string { return "http-probe" }

func (HTTPProbe) Name() string { return "HTTP Probe" }

func (HTTPProbe) Phase() Phase { return PhaseRecon }

func (HTTPProbe) DependsOn() []string { return nil }

func (HTTPProbe) ShouldRun(input AdapterInput) bool {
	return input.Target.Protocol == "http" || input.Target.Protocol == "https"
}

func (a HTTPProbe) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	started := time.Now().UTC()
	url := targetURL(input.Target)
	run := models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    a.ID(),
		Args:      []string{url},
		StartedAt: started,
	}
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		run.ExitCode = 1
		run.RawStderr = reason
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, fmt.Errorf("scope rejected %s: %s", input.Target.Host, reason)
	}
	client := input.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := newHTTPRequestWithAuth(ctx, input, http.MethodGet, url, nil, "nox/0.1 safe-http-probe")
	if err != nil {
		run.ExitCode = 1
		run.RawStderr = err.Error()
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		run.ExitCode = 1
		run.RawStderr = err.Error()
		run.DurationMS = time.Since(started).Milliseconds()
		return AdapterOutput{ToolRun: run}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	title := extractTitle(string(body))
	evidence := map[string]any{
		"url":          url,
		"status_code":  resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"title":        title,
	}
	normalized, _ := json.Marshal(evidence)
	target := input.Target
	target.IsAlive = resp.StatusCode > 0 && resp.StatusCode < 600
	run.RawStdout = string(normalized)
	run.DurationMS = time.Since(started).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return AdapterOutput{
		NewTargets: []models.Target{target},
		ToolRun:    run,
	}, nil
}

func targetURL(target models.Target) string {
	host := target.Host
	if target.Port != 0 && !defaultPort(target.Protocol, target.Port) {
		host = fmt.Sprintf("%s:%d", host, target.Port)
	}
	return fmt.Sprintf("%s://%s/", target.Protocol, host)
}

func defaultPort(protocol string, port int) bool {
	return (protocol == "http" && port == 80) || (protocol == "https" && port == 443)
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	tagStart := strings.Index(lower, "<title")
	if tagStart < 0 {
		return ""
	}
	tagEnd := strings.Index(lower[tagStart:], ">")
	if tagEnd < 0 {
		return ""
	}
	html = html[tagStart+tagEnd+1:]
	lower = strings.ToLower(html)
	end := strings.Index(lower, "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(html[:end])
}
