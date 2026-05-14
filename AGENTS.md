# Codex Guidance for Nox

Use `docs/nox-project-spec.md` as the canonical product specification. Keep `README.md`, `AGENTS.md`, and `docs/implementation-plan.md` updated after every major implementation change.

## Current State

This repo has a buildable backend with per-session SQLite persistence, a synchronous CLI safe scan path, and asynchronous API scan start. Active scans run built-in `http-probe` and `security-headers` plus optional subprocess adapters for `nmap`, `ffuf`, `sqlmap`, and `dalfox`. API scans publish WebSocket lifecycle events at `GET /api/scan/{id}/events` while keeping polling endpoints as fallback. The dashboard reads real sessions, stats, findings, and live progress from the API. The React/Vite frontend builds into `internal/api/web/dist` and is embedded into the Go binary. The backend targets Go 1.26; keep it buildable with `go test ./...` after every change.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Do not discard stdout, stderr, HTTP requests, or HTTP responses.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.

## Suggested Next Tasks

Proceed in order from the lowest incomplete phase in `docs/implementation-plan.md`. Phases 0, 1, 2, 3, and 4 are complete from the repository perspective; the next focus is Phase 5:

1. Evolve the simple dependency-ordered runner into the spec DAG scheduler.
2. Add phase-level lifecycle events while keeping existing dashboard event compatibility.
3. Add concurrency, rate-limit, and timeout controls.
4. Propagate accumulated findings, technologies, and targets to later adapters.
5. Keep cancellation and tool-failure semantics from Phase 3 intact.
