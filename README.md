# NOX

NOX is a local-first web application penetration testing framework. It is designed around scoped scan sessions, normalized findings, evidence preservation, deterministic attack-vector rules, and optional local LLM analysis.

The canonical project specification is tracked at [docs/nox-project-spec.md](docs/nox-project-spec.md).

This repository currently contains the buildable foundation plus the first safe scan path:

- Go CLI entrypoint with `scan`, `serve`, `sessions`, `plugins`, and `report` commands.
- Canonical models for sessions, targets, findings, CVEs, tool runs, and attack vectors.
- Scope validation before scans and per-adapter network requests.
- Per-session SQLite databases in `.nox/sessions/<session-id>.db`.
- Embedded SQLite migrations and manual repository methods.
- Safe built-in `http-probe` and `security-headers` adapters.
- Persisted tool runs and normalized security header findings.
- REST APIs for session create/list/detail/targets and scan status.
- Subprocess plugin JSON contract and runner.
- React/Vite frontend scaffold for dashboard, graph, LLM, and reports.

## Toolchain

NOX targets Go 1.26. Use the latest Go 1.26 patch release for local development and CI.

## Quick Start

```sh
go test ./...
go run . version
go run . scan --target https://example.com
go run . sessions list
go run . serve --host 127.0.0.1 --port 8080
```

The frontend scaffold lives in `web/`. This environment has Node installed but not `npm`, so dependencies have not been installed yet.

## Roadmap

1. Add API endpoints for findings/tool runs and wire the frontend dashboard to real data.
2. Add WebSocket scan lifecycle events for live progress.
3. Add subprocess adapters for tools that can be optional on PATH.
4. Add CVE correlation with cache/offline mode.
5. Implement attack vector evaluation and report generation.
6. Add release packaging and frontend dependency installation.

## Safety Boundary

NOX must treat scope as a hard control. Every network-touching adapter should call scope validation before making outbound requests. Tool failures should be recorded as `tool_runs`, not crash the whole scan unless the database or session context fails.
