# Codex Guidance for NOX

Use `docs/nox-project-spec.md` as the canonical product specification. Keep `README.md`, `AGENTS.md`, and `docs/implementation-plan.md` updated after every major implementation change.

## Current State

This repo has a buildable backend with per-session SQLite persistence, a synchronous CLI safe scan path, and asynchronous API scan start (`http-probe` and `security-headers`). The dashboard reads real sessions, stats, and findings from the API. The React/Vite frontend builds into `internal/api/web/dist` and is embedded into the Go binary. The backend targets Go 1.26; keep it buildable with `go test ./...` after every change.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Do not discard stdout, stderr, HTTP requests, or HTTP responses.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.

## Suggested Next Tasks

1. Add WebSocket scan lifecycle events for live progress.
2. Add optional subprocess adapters for external tools.
3. Add CVE correlation and attack vector evaluation from persisted findings.
4. Add frontend build verification to CI.
5. Add report generation from persisted findings and tool runs.
