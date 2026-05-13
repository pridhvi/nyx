# Nox

Nox is a local-first web application penetration testing framework. It is designed around scoped scan sessions, normalized findings, evidence preservation, deterministic attack-vector rules, and optional local LLM analysis.

The canonical project specification is tracked at [docs/nox-project-spec.md](docs/nox-project-spec.md).

## Authorized Use Only

Nox is intended exclusively for authorized penetration testing, security research, and CTF challenges. Only use Nox against systems you own or have explicit, written permission to test. Unauthorized scanning or exploitation of systems is illegal in most jurisdictions. The authors accept no responsibility for misuse.

This repository currently contains the buildable foundation plus the first safe scan path:

- Go CLI entrypoint with `scan`, `serve`, `sessions`, `plugins`, and `report` commands.
- Canonical models for sessions, targets, findings, CVEs, tool runs, and attack vectors.
- Report metadata models and model validation helpers for spec-aligned ingestion.
- Scope validation before scans and per-adapter network requests.
- Per-session SQLite databases in `.nox/sessions/<session-id>.db`.
- Embedded SQLite migrations and manual repository methods.
- Safe built-in `http-probe` and `security-headers` adapters.
- Persisted tool runs and normalized security header findings.
- REST APIs for session create/list/detail/targets/findings/tool-runs/stats and scan status.
- Asynchronous API scan start with polling-friendly status/read endpoints.
- WebSocket scan lifecycle stream for queued/running/tool/finding/completed progress.
- Dashboard wired to real session, stats, and finding data.
- Dashboard live progress feed for the selected session.
- Subprocess plugin JSON contract and runner.
- Optional subprocess adapters for `nmap`, `ffuf`, `sqlmap`, and `dalfox`, with graceful degradation when tools are unavailable.
- React/Vite frontend scaffold for dashboard, graph, LLM, and reports.

## Toolchain

Nox targets Go 1.26. Use the latest Go 1.26 patch release for local development and CI.

## Quick Start

```sh
make test
make web
make build
go run . version
go run . scan --target https://example.com
go run . sessions list
go run . sessions findings <session-id>
go run . sessions runs <session-id>
go run . serve --host 127.0.0.1 --port 8080
```

The frontend source lives in `web/`. Production frontend assets are built with `npm run build` and embedded into the Go binary from `internal/api/web/dist`.

## Docker

```sh
docker compose up --build
curl http://127.0.0.1:8080/api/health
```

The Docker image bundles the Nox binary and common external scanner tools. Single-binary local builds still work without those tools installed; optional adapters degrade gracefully and record missing binaries as `tool_runs`.

## Roadmap

Implementation now proceeds in order from the lowest incomplete phase in [docs/implementation-plan.md](docs/implementation-plan.md). Phases 0 and 1 are complete from the repository perspective; the next focus is Phase 2:

1. Expand SQLite migrations for HTTP evidence, technologies, CVE matches, attack vectors, LLM history, plugins, and schema migration tracking.
2. Persist raw HTTP request/response evidence separately from normalized findings.
3. Persist technologies, CVE matches, attack vectors, and attack steps.
4. Add database repository methods and tests for the expanded schema.
5. Preserve compatibility for current per-session SQLite databases where possible.

## Safety Boundary

Nox must treat scope as a hard control. Every network-touching adapter should call scope validation before making outbound requests. Tool failures should be recorded as `tool_runs`, not crash the whole scan unless the database or session context fails.
