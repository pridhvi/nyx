# Codex Guidance for NOX

Use `docs/nox-project-spec.md` as the canonical product specification. Keep `README.md`, `AGENTS.md`, and `docs/implementation-plan.md` updated after every major implementation change.

## Current State

This repo has a buildable backend with per-session SQLite persistence and a synchronous safe scan path (`http-probe` and `security-headers`). The backend targets Go 1.26; keep it buildable with `go test ./...` after every change. The frontend is scaffolded as React/Vite, but package installation is pending because `npm` is not currently available in this environment.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Do not discard stdout, stderr, HTTP requests, or HTTP responses.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.

## Suggested Next Tasks

1. Add findings and tool-run API endpoints.
2. Wire the React dashboard to real session/finding data.
3. Add WebSocket scan lifecycle events before making scans asynchronous.
4. Add optional subprocess adapters for external tools.
5. Add CVE correlation and attack vector evaluation from persisted findings.
