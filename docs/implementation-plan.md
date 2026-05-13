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

Status: implemented. CLI scans run synchronously; API scan start runs asynchronously.

## Phase 2.5: API/UI Read Model

- Add REST endpoints for findings and tool runs.
- Add session detail API aggregation for target/finding/tool-run counts.
- Wire the dashboard to real API data.
- Add CLI inspection for findings and tool runs.

Status: implemented.

## Phase 2.6: Live Progress

- Add WebSocket scan lifecycle events for queued, running, tool started, tool completed, finding found, failed, and completed states.
- Keep the existing polling status endpoints as fallback.
- Surface live progress in the dashboard.

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

- Expand React UI beyond the dashboard into session detail, attack graph, LLM, and reports views.
- Add Docker and release builds.
- Add GitHub Actions for tests and lint.
- Add plugin SDK examples.
