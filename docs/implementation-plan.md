# NOX Implementation Plan

## Phase 0: Foundation

- Create buildable Go module and CLI.
- Add canonical model structs and initial migration.
- Add plugin contract and subprocess runner.
- Add frontend scaffold and repository guidance.

## Phase 1: Local Session Store

- Add SQLite driver and migration runner.
- Store one database file per engagement.
- Implement session create/list/show/delete.
- Add API endpoints for sessions and health.

Status: implemented.

## Phase 2: Safe Built-In Scanning

- Implement scope-aware `http-probe`.
- Implement `security-headers`.
- Add DAG runner with dependency ordering and tests.
- Persist tool runs and normalized findings.

Status: implemented as synchronous scans. WebSocket scan lifecycle events are deferred until the scan runner becomes asynchronous.

## Phase 2.5: API/UI Read Model

- Add REST endpoints for findings and tool runs.
- Add session detail API aggregation for target/finding/tool-run counts.
- Wire the dashboard to real API data.
- Keep scans synchronous until WebSocket progress is available.

## Phase 3: External Tool Adapters

- Add subprocess adapter wrappers for `nmap`, `ffuf`, `sqlmap`, and `dalfox`.
- Record `tool_runs` for success and failure.
- Normalize findings into the shared schema.

## Phase 4: Correlation

- Add technology inventory.
- Add CVE lookup interfaces with cache and offline mode.
- Add rule-based attack vector engine.

## Phase 5: Reporting and LLM

- Generate Markdown and HTML reports from persisted evidence.
- Add OpenAI-compatible local LLM client.
- Use LLM to annotate reports and attack narratives.

## Phase 6: Product Polish

- Wire React UI to APIs.
- Add Docker and release builds.
- Add GitHub Actions for tests and lint.
- Add plugin SDK examples.
