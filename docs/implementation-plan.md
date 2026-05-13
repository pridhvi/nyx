# Nox Implementation Plan

This plan is the execution roadmap for the canonical product specification in
`docs/nox-project-spec.md`. It intentionally preserves the current MVP work and
builds on top of it. Existing code should be extended, not discarded, unless a
specific implementation is proven incompatible with the spec.

## Planning Rules

- `docs/nox-project-spec.md` is the source of truth for product behavior,
  architecture, API surface, data models, scanner coverage, UI pages, packaging,
  and safety expectations.
- `README.md`, `AGENTS.md`, and this plan must be updated after every major
  implementation change.
- Scope validation is a hard security boundary. Every network request and every
  subprocess scanner invocation must validate scope first.
- Evidence is first-class data. Store raw stdout, stderr, HTTP request/response
  evidence, and normalized output where the schema supports it.
- All scanner output must normalize into `internal/models.Finding` or one of the
  related canonical models before analysis.
- External tools are optional. Missing binaries, unavailable wordlists,
  subprocess timeouts, and non-zero exits are recorded as `tool_runs`; they
  should not prevent the rest of a scan from continuing.
- LLM output can annotate, summarize, and suggest, but deterministic rules decide
  correctness-critical attack vector logic.
- Default operation remains local-first: no telemetry, no required cloud API
  keys, and air-gap capable paths where the spec requires them.

## Status Legend

- `Implemented`: Present and aligned enough for the current milestone.
- `Partial`: Useful current implementation exists, but spec alignment remains.
- `Pending`: Not yet implemented.
- `Planned Later`: Spec-required or spec-mentioned work intentionally deferred
  until prerequisite phases land.

## Implementation Order

Work should proceed from the lowest-numbered phase that still has remaining
acceptance criteria. Phases 0 and 1 are complete from the repository
perspective, so the next implementation focus is Phase 2: Database And
Persistence. Later phases can be inspected for context, but implementation
should not skip ahead unless a Phase 2 task explicitly depends on later-phase
context.

## Current Baseline

The current repo is not greenfield. These items are valuable baseline work and
must be carried forward:

- **Foundation:** Buildable Go module and CLI entrypoint with `scan`, `serve`,
  `sessions`, `plugins`, `report`, and `version` command surfaces.
- **Models and migration:** Canonical model structs for sessions, targets,
  findings, CVEs, tool runs, attack vectors, and report metadata, plus an
  initial SQLite schema.
- **Session store:** Per-session SQLite persistence in `.nox/sessions`, with
  create/list/show/delete support.
- **Scope safety:** Scope checker for hosts, URLs, and CIDRs.
- **Adapters:** Adapter interface, registry, plugin JSON contract, subprocess
  helper, built-in `http-probe`, and built-in `security-headers`.
- **MVP external adapter slice:** Optional subprocess wrappers for `nmap`,
  `ffuf`, `sqlmap`, and `dalfox`. This is a useful MVP slice across spec
  reconnaissance, enumeration, and vulnerability scanning. It is not a
  replacement for the full spec pipeline.
- **Runner:** Simple dependency-ordered runner with persisted tool runs and
  normalized findings. This should be incrementally evolved into the spec DAG
  scheduler instead of being thrown away.
- **API:** Health, tools, sessions, targets, findings, tool runs, stats, scan
  start, scan status, and scan lifecycle WebSocket event stream.
- **WebSocket progress:** Current endpoint is `GET /api/scan/{id}/events` with
  bounded event replay. Keep it and add a compatibility alias for the spec route
  `WS /ws/scan/{id}` later.
- **Frontend:** React/Vite dashboard that reads real API data and displays live
  scan progress. Built assets are embedded into `internal/api/web/dist`.
- **Verification:** `go test ./...` and `npm run build` pass for the current
  working set.

---

## Phase 0: Repository, Safety, And Toolchain Foundation

**Status:** Implemented  
**Spec sections covered:** 1, 2, 3, 20, 21, 22, 23

### Existing Baseline

- Go module and CLI exist.
- React/Vite frontend exists and builds into embedded assets.
- Repository guidance exists in `AGENTS.md`.
- README describes local-first purpose and safety boundary.
- README and CLI help include authorized-testing legal guidance.
- Makefile targets exist for build, dev, test, integration-test placeholder,
  lint, web, sqlc placeholder, migration placeholder, cleanup, and release
  snapshot.
- Dockerfile and docker-compose exist for Nox plus Ollama services.
- GoReleaser snapshot configuration exists for embedded-frontend single-binary
  release artifacts.
- GitHub Actions CI runs Makefile test/web/build workflows, Docker image build,
  Compose config validation, and GoReleaser snapshot release.
- Local Docker validation now covers image build, `nox version`, CLI help,
  docker-compose startup, and `/api/health` with writable session storage.

### Remaining Work

- Replace placeholder `test-integration`, `sqlc`, and `migrate-up` Makefile
  behavior when those later systems are fully implemented.
- Add deeper Docker smoke tests once the scan pipeline has deterministic
  fixture targets.

### Spec Alignment Follow-ups

- Do not remove current local development workflow while adding Docker and
  release tooling.
- Keep external tools optional outside the Docker image.
- Ensure all docs preserve the local-first, air-gap-capable design principles.

### Acceptance Criteria

- README and CLI visibly warn that Nox is for authorized testing only.
- `make build`, `make test`, and `make web` work.
- CI validates that the Docker image builds.
- CI validates Docker Compose configuration for Nox and Ollama services.
- Local Docker smoke validation can start Nox and Ollama and report API health
  with `db_dir_ready: true`.
- CI validates release snapshot generation for embedded-frontend single-binary
  artifacts.

---

## Phase 1: Core Data Models

**Status:** Implemented  
**Spec sections covered:** 5.1, 5.2, 5.3, 5.4, 5.5, 5.6

### Existing Baseline

- Models exist for:
  - `Finding`
  - `HTTPEvidence`
  - `Target`
  - `Technology`
  - `Session`
  - `CVEMatch`
  - `AttackVector`
  - `AttackStep`
  - `ToolRun`
  - `Report`
  - `ReportSection`
- Findings support severity, type, confidence, CVSS, remediation, URL,
  parameter, method, raw evidence, normalized evidence, tags, and CVE matches.
- Sessions support scan mode, in-scope/out-of-scope lists, LLM fields, counts,
  and timestamps.
- CVE matches include source, CVSS v3 score/vector, affected/fixed version
  fields, references, exploit availability, patch availability, and confidence.
- Attack vectors include ordered steps, prerequisite finding IDs, severity,
  confidence, OWASP category, narrative, LLM reviewed state, and LLM notes.
- Report metadata models cover md/html/pdf formats, executive/technical modes,
  report sections, linked finding/CVE/vector IDs, and generation metadata.
- Model validation helpers exist for enum values, required identifiers, score
  ranges, confidence ranges, target ports, attack steps, and report sections.
- Serialization tests cover findings, CVE matches, attack vectors, tool runs,
  report metadata, sessions, targets, technologies, and validation failures.

### Remaining Work

- None for Phase 1. Persistence, API exposure, and report generation for the new
  model fields are handled by later phases.

### Spec Alignment Follow-ups

- Preserve current models where possible and extend them through migrations in
  Phase 2.
- Do not break existing API JSON without adding compatibility handling.

### Acceptance Criteria

- All spec model concepts are represented in Go structs.
- Model tests cover serialization for findings, CVE matches, attack vectors,
  tool runs, and report metadata.
- API responses can expose the model fields needed by the full UI and reports
  once Phase 2 persists and Phase 13 exposes them.

---

## Phase 2: Database And Persistence

**Status:** Partial  
**Spec sections covered:** 3.4, 6

### Existing Baseline

- SQLite is the default database via `modernc.org/sqlite`.
- The repo stores one database file per engagement/session.
- Initial migration creates core session, target, finding, and tool run tables.
- Store methods support create/list/show/delete sessions, targets, findings,
  tool runs, stats, counts, and status updates.

### Remaining Work

- Expand migrations to cover the complete spec schema:
  - sessions
  - targets
  - findings
  - HTTP evidence
  - tool runs
  - technologies
  - CVE matches
  - attack vectors
  - LLM conversations/history
  - plugins
  - schema migrations
- Persist raw HTTP evidence separately where required:
  - request raw
  - response raw
  - status code
  - response time
- Persist technologies detected by fingerprinting adapters.
- Persist CVE matches linked to technologies or findings.
- Persist attack vectors and attack steps as structured JSON.
- Persist LLM conversation history and tool-call traces.
- Add migration tests for upgrades and rollbacks where practical.
- Evaluate sqlc adoption:
  - Spec prefers sqlc-generated typed queries.
  - Current handwritten store can remain until migration complexity justifies
    sqlc conversion.
- Plan optional PostgreSQL support as a later team-deployment feature.

### Spec Alignment Follow-ups

- Keep current per-session SQLite path and existing databases compatible.
- Add migrations incrementally instead of replacing the initial schema.
- Do not introduce an ORM.

### Acceptance Criteria

- New sessions are stored as complete engagement databases.
- All scanner evidence, normalized findings, technologies, CVEs, attack vectors,
  and LLM conversations can be persisted and reloaded.
- Existing API and CLI session commands continue to work with migrated DBs.
- Tests verify required tables and representative insert/list flows.

---

## Phase 3: Scope Validation And Session Lifecycle

**Status:** Partial  
**Spec sections covered:** 2, 5.3, 16, 17, 18

### Existing Baseline

- Scope checker supports URLs, hosts, wildcard hosts, IPs, and CIDRs.
- Session creation validates the initial target.
- Built-in and external MVP adapters validate target host scope before network
  requests or subprocess scanner invocation.
- Session statuses include pending, running, completed, failed, and cancelled.

### Remaining Work

- Add configuration-backed default scan settings:
  - default mode
  - default concurrency
  - default rate limit
  - timeout per tool
- Add stop/cancel support for running scans.
- Make session-level failure semantics match the spec:
  - adapter failures are non-fatal
  - DB/session context failures can fail the scan
  - cancellation sets cancelled status
- Add persistent scan options:
  - enabled phases
  - selected tools
  - LLM model/base URL
  - no-LLM flag
  - rate limits and concurrency caps
- Add structured logging with configurable levels.
- Add tests for out-of-scope enforcement across built-in HTTP adapters and
  subprocess adapters.

### Spec Alignment Follow-ups

- Keep current scope checker and extend it; do not replace the security boundary.
- Every new adapter must receive the scope checker through `AdapterInput`.

### Acceptance Criteria

- Out-of-scope targets never cause outbound network traffic.
- Cancelling a scan stops pending/running adapter work.
- Tool failures are recorded in `tool_runs` without failing the entire scan.
- Session status transitions are covered by tests.

---

## Phase 4: Adapter System, Registry, And Plugin Contract

**Status:** Partial  
**Spec sections covered:** 3.5, 7

### Existing Baseline

- Adapter interface exists with ID, name, phase, dependencies, `ShouldRun`, and
  `Run`.
- Global registry exists.
- Subprocess JSON plugin contract exists.
- Direct subprocess command helper exists for scanner CLIs.
- MVP external adapters record `tool_runs` for missing binaries, timeouts,
  non-zero exits, and parser-normalized findings.

### Remaining Work

- Complete plugin management:
  - install/register plugin binaries
  - persist plugin metadata
  - list configured plugins
  - load plugin directories from config
- Expand plugin request/response schema if needed for:
  - scan config
  - tool-specific config
  - evidence artifacts
  - technologies
  - new targets
- Add tool path auto-detection and config overrides for all external tools.
- Add adapter fixture test structure under `testdata`.
- Add normalized parser tests for each external adapter.
- Add clear adapter authoring documentation.

### Spec Alignment Follow-ups

- Keep current subprocess JSON-RPC contract as the initial plugin mechanism.
- Treat `hashicorp/go-plugin` or gRPC plugins as future optimization only.

### Acceptance Criteria

- `nox plugins list` reports built-in adapters and configured plugins.
- Plugin binaries can be configured and invoked through the adapter contract.
- Missing or failing plugin binaries produce persisted `tool_runs`.
- Adapter tests prove output normalization is deterministic.

---

## Phase 5: DAG Scheduler And Live Scan Events

**Status:** Partial  
**Spec sections covered:** 8, 9, 13 WebSocket event format

### Existing Baseline

- Runner orders adapters by dependencies.
- Scan lifecycle events exist for queued, running, tool started, tool completed,
  finding found, failed, and completed states.
- API exposes `GET /api/scan/{id}/events` as the current WebSocket endpoint.
- Dashboard consumes live events and retains REST polling fallback.

### Remaining Work

- Evolve simple runner into the full spec DAG scheduler:
  - build graph from registered adapters
  - topologically sort into executable phases
  - run same-phase adapters concurrently where safe
  - enforce per-tool semaphores
  - enforce global and per-tool rate limits
  - propagate accumulated findings, targets, and technologies to later adapters
  - handle context cancellation and timeouts
  - trigger CVE correlator and attack vector engine after scanner phases
- Add phase-level events:
  - phase started
  - phase completed
  - tool error
  - scan cancelled
- Add WebSocket compatibility alias for spec route `WS /ws/scan/{id}` while
  keeping `GET /api/scan/{id}/events`.
- Align event payloads with spec while maintaining current client compatibility.

### Spec Alignment Follow-ups

- Do not discard current runner; refactor it incrementally into DAG/scheduler
  components.
- Keep existing event types stable for the dashboard.

### Acceptance Criteria

- DAG tests cover dependency order, cycle detection, missing dependencies, and
  same-phase parallel execution.
- Rate-limit and semaphore behavior is testable.
- Scan events stream phase, tool, finding, error, completion, and cancellation
  updates.
- Existing polling endpoints remain valid fallback.

---

## Phase 6: Reconnaissance Adapters

**Status:** Partial  
**Spec sections covered:** 8 Phase 1, 22 step 6

### Existing Baseline

- Built-in `http-probe` provides a lightweight safe HTTP probe.
- MVP subprocess `nmap` records open-port findings when available.

### Remaining Work

- Implement full reconnaissance pipeline:
  - `subfinder` as Go library
  - `dnsx` as Go library
  - `naabu` as Go library
  - `httpx` as Go library
  - `nmap` using the spec-preferred Go wrapper, or keep subprocess `nmap` as a
    transitional implementation with a documented migration path
  - `whois` subprocess
  - `crt.sh` HTTP API client
  - `waybackurls` subprocess
- Normalize outputs into:
  - targets
  - open ports
  - service/version findings
  - status codes
  - page titles
  - discovered URLs
  - raw evidence/tool runs
- Add dependency handling:
  - `subfinder`, `dnsx`, `nmap`, `crt.sh`, and `whois` can run early
  - `httpx` depends on discovered hosts/ports
  - `waybackurls` depends on discovered domains/subdomains

### Spec Alignment Follow-ups

- Do not remove current `http-probe`; it can remain as a safe built-in probe
  beside or before full `httpx`.
- Keep current subprocess `nmap` useful until Go-wrapper parity is implemented.

### Acceptance Criteria

- Recon phase builds a complete in-scope target map.
- New targets are persisted and available to later phases.
- Missing external recon tools degrade gracefully.
- Fixture tests cover parser normalization.

---

## Phase 7: Fingerprinting Adapters

**Status:** Partial  
**Spec sections covered:** 8 Phase 2

### Existing Baseline

- `security-headers` adapter identifies missing CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, and Referrer-Policy.
- Dashboard and API expose these normalized findings.

### Remaining Work

- Implement full fingerprinting pipeline:
  - `whatweb` subprocess
  - nuclei technology templates
  - `testssl.sh` subprocess
  - GraphQL introspection check
  - OpenAPI/Swagger discovery
  - WPScan subprocess
  - droopescan subprocess
- Persist detected technologies with name, version, category, confidence, and
  source tool.
- Persist TLS/certificate issues and exposed documentation findings.
- Use fingerprinting output as input for CVE correlation and attack vectors.

### Spec Alignment Follow-ups

- Keep `security-headers` as the initial built-in fingerprinting adapter.
- Add technologies table/store methods before adapters that emit technologies.

### Acceptance Criteria

- Live HTTP/S targets receive fingerprinting coverage.
- Technologies with versions are stored for CVE correlation.
- TLS, CMS, GraphQL, OpenAPI/Swagger, and security header findings normalize
  into the shared finding schema.

---

## Phase 8: Enumeration Adapters

**Status:** Partial  
**Spec sections covered:** 8 Phase 3

### Existing Baseline

- MVP `ffuf` subprocess adapter discovers web paths when installed and a common
  wordlist exists.

### Remaining Work

- Implement full enumeration pipeline:
  - `ffuf` or `feroxbuster`
  - `arjun`
  - `linkfinder`
  - `gitleaks` or `trufflehog`
  - CORS check
  - S3/GCS enumeration
- Normalize:
  - hidden directories and files
  - hidden HTTP parameters
  - JavaScript endpoints
  - exposed secrets
  - CORS misconfigurations
  - public cloud bucket exposures
- Feed discovered URLs and parameters into vulnerability scanning.
- Add configurable wordlists and rate limits.

### Spec Alignment Follow-ups

- Current `ffuf` adapter is an MVP slice and should be extended with configured
  wordlists, response filtering, and better path classification.

### Acceptance Criteria

- Enumeration produces persisted findings and, where useful, discovered URLs or
  target metadata for later phases.
- Secrets and exposed storage checks preserve raw evidence.
- CORS findings include tags needed by attack vector rules.

---

## Phase 9: Vulnerability Scanning Adapters

**Status:** Partial  
**Spec sections covered:** 8 Phase 4

### Existing Baseline

- MVP `sqlmap` subprocess adapter runs against query URLs.
- MVP `dalfox` subprocess adapter runs against query URLs.
- Both validate scope and persist `tool_runs`.

### Remaining Work

- Implement full vulnerability scanning pipeline:
  - nuclei vulnerability templates
  - `sqlmap`
  - `dalfox`
  - SSRFmap
  - `jwt_tool`
  - OAuth checks
  - SSTI detection
  - XXE fuzzing
  - `nikto`
- Use enumeration output to target parameters/endpoints safely.
- Add per-tool active-mode safeguards, timeouts, and rate limits.
- Normalize confirmed vulnerabilities with confidence, severity, remediation,
  raw evidence, and relevant tags.
- Add optional higher-risk modes only when explicitly configured.

### Spec Alignment Follow-ups

- Keep current `sqlmap` and `dalfox` wrappers, but expand targeting beyond only
  the initial query URL after parameter discovery exists.

### Acceptance Criteria

- Vulnerability scanning only runs in appropriate scan modes.
- Dangerous checks are bounded by scope, rate limits, and timeout settings.
- Confirmed vulnerability findings support attack vector and report generation.

---

## Phase 10: CVE Intelligence

**Status:** Partial  
**Spec sections covered:** 5.4, 11, 16 CVE settings

### Existing Baseline

- CVE model exists.
- No complete CVE client/correlator exists yet.

### Remaining Work

- Add `internal/cve` package with clients for:
  - NVD API v2
  - OSV.dev
  - CIRCL CVE Search
  - vulners.com
  - Exploit-DB offline mirror/CSV
  - GitHub Security Advisories
- Add cache with configurable TTL.
- Add offline mode using local mirrors.
- Correlate technology name/version to CVEs.
- Score confidence:
  - exact version match
  - version range match
  - product-only match
- Persist CVE matches and references.
- Mark exploit availability and patch/fix version where known.
- Automatically draft attack vectors for exploitable CVEs with score >= 7.0.

### Spec Alignment Follow-ups

- Technology persistence from fingerprinting is a prerequisite for full CVE
  correlation.

### Acceptance Criteria

- CVE correlation runs after scan phases.
- CVE matches are linked to technologies or findings.
- CVE cache works without repeated remote calls.
- Offline mode works with local data sources.

---

## Phase 11: Attack Vector Engine

**Status:** Partial  
**Spec sections covered:** 5.5, 12

### Existing Baseline

- Attack vector models and initial rules package exist.
- Full engine, persistence, scoring, and API/UI exposure are incomplete.

### Remaining Work

- Implement deterministic rule engine:
  - conditions by tool ID
  - finding type
  - minimum severity
  - URL contains
  - tag contains
  - parameter present
- Implement attack chain templates and confidence scoring.
- Add default rules from the spec:
  - reflected XSS with missing CSP
  - SSRF to cloud metadata
  - weak JWT secret
  - unauthenticated SQL injection
  - exposed admin panel with weak/default auth indicators
  - CORS wildcard credentials
- Persist generated attack vectors and steps.
- Add LLM augmentation pass after deterministic vectors exist.
- Keep LLM notes separate from deterministic rule output.

### Spec Alignment Follow-ups

- Fix rule references to current tool IDs where needed, while preserving spec
  semantics.
- Ensure findings include tags required by attack rules.

### Acceptance Criteria

- Rule tests cover each default attack vector rule.
- Generated vectors include steps, OWASP category, severity, confidence, and
  source findings.
- LLM review can annotate but not overwrite deterministic facts without trace.

---

## Phase 12: LLM Integration

**Status:** Pending  
**Spec sections covered:** 3.2 LLM dependency, 5.3 LLM session fields, 10

### Existing Baseline

- Session model includes LLM model/base URL fields.
- Placeholder UI page exists for LLM chat.

### Remaining Work

- Add OpenAI-compatible LLM client supporting:
  - Ollama
  - LM Studio
  - llama.cpp OpenAI-compatible servers
  - OpenAI-compatible cloud endpoints when configured
- Add LLM config:
  - provider
  - base URL
  - API key
  - model
  - max tokens
  - temperature
- Add context builder that summarizes:
  - session
  - targets
  - technologies
  - findings
  - attack vectors
  - stats
- Truncate long evidence fields before sending to LLM.
- Add tool definitions:
  - `request_scan`
  - `lookup_cve`
  - `search_cves_for_technology`
  - `get_session_findings`
- Add analyst loop with visible tool-call audit trail.
- Persist conversation history.
- Add system prompt from the spec.

### Spec Alignment Follow-ups

- LLM integration must remain optional and local-first by default.
- Do not require cloud API keys for normal operation.

### Acceptance Criteria

- LLM chat can answer from structured session context.
- LLM tool calls are constrained by scope and recorded.
- Full-session analysis can annotate reports and attack narratives.
- Operation degrades gracefully when no LLM is configured.

---

## Phase 13: REST API And Auth

**Status:** Partial  
**Spec sections covered:** 13

### Existing Baseline

- Implemented endpoints include:
  - `GET /api/health`
  - `GET /api/tools`
  - `GET /api/sessions`
  - `GET /api/sessions/{id}`
  - `GET /api/sessions/{id}/targets`
  - `GET /api/sessions/{id}/findings`
  - `GET /api/sessions/{id}/tool-runs`
  - `GET /api/sessions/{id}/stats`
  - `GET /api/scan/{id}/status`
  - `GET /api/scan/{id}/events`
  - `POST /api/scan/start`

### Remaining Work

- Add missing scan/session endpoints:
  - `POST /api/scan/{id}/stop`
  - `DELETE /api/sessions/{id}`
  - `GET /api/sessions/{id}/vectors`
  - `GET /api/sessions/{id}/cves`
  - `GET /api/sessions/{id}/report?format=html|pdf|md`
  - `POST /api/sessions/{id}/llm/chat`
  - `POST /api/sessions/{id}/llm/analyse`
  - `GET /api/sessions/{id}/llm/history`
  - `WS /ws/scan/{id}` compatibility alias
- Add filtering/pagination for findings:
  - severity
  - type
  - tool
  - page
  - limit
  - CVE/exploit filters where supported
- Add local API-key auth for network-accessible UI/API.
- Expand health output:
  - DB readiness
  - LLM reachability
  - configured tool availability
  - session directory status

### Spec Alignment Follow-ups

- Keep current endpoints stable while adding spec endpoints.
- Keep current scan event endpoint as the canonical internal route unless route
  migration is intentionally scheduled.

### Acceptance Criteria

- API tests cover every spec endpoint.
- Auth can be disabled for localhost-only use and enabled for network access.
- Frontend can retrieve all data needed by spec UI pages.

---

## Phase 14: CLI And Configuration

**Status:** Partial  
**Spec sections covered:** 14, 16

### Existing Baseline

- CLI supports scan, serve, sessions, plugins, report, version.
- Scan supports target, name, mode, and out-of-scope.
- Serve supports host and port.
- Sessions supports list/show/delete/findings/runs.

### Remaining Work

- Add full scan flags:
  - `--phases`
  - `--tools`
  - `--llm-model`
  - `--llm-url`
  - `--no-llm`
  - `--concurrency`
  - `--rate-limit`
- Add report flags:
  - `--format html|pdf|md`
  - `--output`
  - `--mode executive|technical`
- Add LLM commands:
  - `nox llm chat <session-id>`
  - `nox llm analyse <session-id>`
- Add config commands:
  - `nox config init`
  - `nox config show`
- Implement config file at `~/.nox/config.yaml` with:
  - LLM settings
  - database settings
  - server settings
  - default scan settings
  - CVE intelligence settings
  - tool paths
  - plugin directories
- Define precedence:
  - CLI flags
  - environment variables
  - config file
  - defaults

### Spec Alignment Follow-ups

- Preserve current simple CLI behavior while expanding flags and config.
- Keep zero-config `nox scan --target example.com` working.

### Acceptance Criteria

- Config init writes a complete default config.
- CLI commands can override config.
- Tool paths, LLM settings, CVE settings, and scan defaults are usable by
  backend components.

---

## Phase 15: Reporting

**Status:** Pending  
**Spec sections covered:** 3.2 report dependencies, 15.6

### Existing Baseline

- CLI report command placeholder exists.
- Reports UI page placeholder exists.

### Remaining Work

- Add report generator package.
- Support output formats:
  - Markdown
  - HTML
  - PDF
- Support report modes:
  - executive
  - technical
- Include report sections:
  - executive summary
  - scope and methodology
  - critical/high findings
  - medium/low findings summary
  - attack vectors with step-by-step chains
  - CVE matches with patch availability
  - remediation roadmap
  - raw tool output appendix
- Use LLM-generated narrative only when LLM is configured; otherwise use
  deterministic summaries.
- Add API and CLI report generation.

### Spec Alignment Follow-ups

- Reporting depends on complete findings, evidence, CVEs, and attack vectors for
  full value, but basic Markdown/HTML can land earlier.

### Acceptance Criteria

- `nox report <session-id> --format md|html|pdf` works.
- Report API returns requested format.
- Reports include persisted evidence and no fabricated conclusions.

---

## Phase 16: Web UI

**Status:** Partial  
**Spec sections covered:** 3.3, 15

### Existing Baseline

- React/Vite app exists.
- Dashboard lists sessions, stats, findings, and live progress.
- Placeholder pages exist for attack graph, LLM, and reports.

### Remaining Work

- Implement Dashboard `/`:
  - active/recent sessions
  - quick-start scan form
  - global finding stats
- Implement Session Detail `/sessions/:id`:
  - metadata
  - live phase tracker
  - tool status indicators
  - real-time finding counter
  - sortable/filterable findings table
  - severity distribution chart
  - tool coverage matrix
- Implement Attack Graph `/sessions/:id/graph`:
  - Cytoscape graph
  - target, technology, finding, and attack vector nodes
  - edges for discovered-by, exploits, leads-to, affects
  - severity/category filters
  - details side panel
- Implement Findings `/sessions/:id/findings`:
  - full findings table
  - raw evidence expansion
  - HTTP request/response expansion
  - CVE matches
  - severity/type/tool/OWASP/CVE/exploit filters
  - export selected
  - notes/severity adjustment if supported
- Implement LLM Chat `/sessions/:id/llm`:
  - conversation history
  - visible LLM tool calls
  - suggested prompts
- Implement Reports `/sessions/:id/report`:
  - HTML preview
  - executive/technical toggle
  - PDF and Markdown download

### Spec Alignment Follow-ups

- Keep current dashboard layout and evolve it into the spec dashboard.
- Do not add decorative landing pages; the first screen remains the app.

### Acceptance Criteria

- Every spec UI page has a route and real API data.
- Dashboard remains usable while new detail pages are added.
- Frontend build is verified in CI.

---

## Phase 17: Docker, Makefile, And Release Packaging

**Status:** Pending  
**Spec sections covered:** 3.6, 20, 21

### Existing Baseline

- Frontend build embeds assets into the Go binary.
- Dockerfile builds the frontend, compiles the Go binary, and produces a Kali
  runtime image with common optional scanner tools installed.
- docker-compose starts Nox and Ollama with persistent volumes.
- Makefile covers build, dev, test, web build, lint, placeholder integration
  tests, placeholder migrations/sqlc, cleanup, and release snapshots.
- GoReleaser snapshot configuration exists for embedded-frontend binaries.

### Remaining Work

- Replace placeholder integration-test, sqlc, and migration targets as those
  systems mature.
- Add config file mount examples once Phase 14 configuration is implemented.
- Expand release metadata when versioning, signing, and distribution channels
  are decided.
- Add end-to-end Docker scan smoke tests with controlled vulnerable fixtures.

### Spec Alignment Follow-ups

- External scanner availability in Docker should be better than single-binary
  mode, but single-binary mode must remain useful with graceful degradation.

### Acceptance Criteria

- Docker image can serve the UI and pass API health checks.
- docker-compose starts Nox and Ollama.
- Makefile targets work locally and in CI.
- Release artifacts include embedded frontend.
- A later fixture-backed smoke test verifies Docker scan execution end to end.

---

## Phase 18: Testing And CI

**Status:** Partial  
**Spec sections covered:** 19

### Existing Baseline

- Go unit/API tests exist.
- Adapter parser tests exist for MVP external adapters.
- Frontend builds locally with `npm run build`.

### Remaining Work

- Add unit tests for:
  - scope checker
  - DAG topological sort
  - scheduler/rate limits
  - finding normalization helpers
  - CVE correlator matching
  - attack vector rule evaluation
- Add fixture tests for every adapter using `testdata`.
- Add API tests for all REST and WebSocket endpoints.
- Add frontend build verification to CI.
- Add linting for Go and frontend.
- Add opt-in integration tests using Docker and vulnerable targets such as DVWA
  or Juice Shop.
- Add test coverage for missing optional tools and graceful degradation.

### Spec Alignment Follow-ups

- CI should not require dangerous external scanners or vulnerable targets unless
  explicitly running integration tests.

### Acceptance Criteria

- `go test ./...` passes.
- Frontend build passes in CI.
- Adapter parser tests do not require scanner binaries.
- Integration tests are opt-in and documented.

---

## Phase 19: Spec Traceability Matrix

**Status:** Partial  
**Spec sections covered:** 1-23

| Spec section | Implementation phase | Current status | Notes |
| --- | --- | --- | --- |
| 1. Project Overview | Phase 0 | Partial | Local-first dual-interface direction exists; full product scope remains. |
| 2. Design Principles | Phases 0, 3, 4, 5, 11, 12 | Partial | Scope/evidence/normalization are started; full DAG and LLM constraints pending. |
| 3. Tech Stack | Phases 0, 2, 12, 15, 16, 17 | Partial | Go, SQLite, React/Vite exist; many planned deps and packaging remain. |
| 3.1 Backend Go | Phases 0, 5 | Partial | Current Go target is 1.26; scheduler and embedded tool libs pending. |
| 3.2 Dependencies | Phases 0, 10, 12, 15, 17, 18 | Partial | SQLite/WebSocket present; many listed deps not yet added. |
| 3.3 Frontend | Phase 16 | Partial | Dashboard exists; full page set pending. |
| 3.4 Database | Phase 2 | Partial | SQLite exists; full schema and optional Postgres pending. |
| 3.5 Plugin System | Phase 4 | Partial | JSON contract exists; install/persist/load flow pending. |
| 3.6 Packaging | Phase 17 | Partial | Docker, Compose, Makefile, CI build, and snapshot release exist; deeper release hardening pending. |
| 4. Project Structure | All phases | Partial | Current structure is close but not complete. |
| 5. Core Data Models | Phase 1 | Implemented | Canonical models, report metadata models, additive CVE version fields, and serialization/validation tests exist. |
| 6. Database Schema | Phase 2 | Partial | Initial schema exists; complete schema pending. |
| 7. Tool Adapter System | Phase 4 | Partial | Interface/registry/runners exist; plugin ecosystem pending. |
| 8. Tool Pipeline | Phases 6-9 | Partial | MVP built-ins and four external wrappers exist; full pipeline pending. |
| 9. DAG Engine | Phase 5 | Partial | Dependency order exists; concurrency/rate limits/phase engine pending. |
| 10. LLM Integration | Phase 12 | Pending | Session fields/placeholders exist only. |
| 11. CVE Intelligence | Phase 10 | Pending | Model exists; engine pending. |
| 12. Attack Vector Engine | Phase 11 | Partial | Models/rules started; full engine pending. |
| 13. REST API Surface | Phase 13 | Partial | Core read/start endpoints exist; stop/vector/CVE/LLM/report/auth pending. |
| 14. CLI Commands | Phase 14 | Partial | Core commands exist; full flags/config/LLM/report pending. |
| 15. Web UI Pages | Phase 16 | Partial | Dashboard exists; full session pages pending. |
| 16. Configuration File | Phase 14 | Pending | Config system pending. |
| 17. Scope Validation | Phase 3 | Partial | Checker exists; full coverage tests/config integration pending. |
| 18. Error Handling & Logging | Phases 3, 4, 5 | Partial | Tool failures persist; structured logging/config pending. |
| 19. Testing Strategy | Phase 18 | Partial | Tests exist; full coverage pending. |
| 20. Docker Setup | Phase 17 | Partial | Dockerfile and compose exist and pass local smoke validation; fixture-backed scan smoke tests pending. |
| 21. Makefile | Phase 17 | Partial | Core Makefile targets exist; placeholder migration/sqlc/integration behavior will be replaced later. |
| 22. Build Order Recommendation | This plan | Implemented | This roadmap follows the spec build order while preserving current work. |
| 23. Security & Legal Notes | Phase 0 | Implemented | README and CLI help include prominent authorized-use warnings; scope remains a hard implementation boundary. |

## Coverage Check Terms

The plan intentionally includes these spec terms so future audits can quickly
confirm coverage:

- `subfinder`, `dnsx`, `naabu`, `httpx`, `nmap`, `whois`, `crt.sh`,
  `waybackurls`
- `whatweb`, `nuclei`, `testssl.sh`, `GraphQL`, `OpenAPI`, `Swagger`,
  `WPScan`, `droopescan`
- `ffuf`, `feroxbuster`, `arjun`, `linkfinder`, `gitleaks`, `trufflehog`,
  `CORS`, `S3`, `GCS`
- `sqlmap`, `dalfox`, `SSRFmap`, `jwt_tool`, `OAuth`, `SSTI`, `XXE`, `nikto`
- `NVD`, `OSV.dev`, `CIRCL`, `vulners`, `Exploit-DB`,
  `GitHub Security Advisories`
- `Ollama`, `LM Studio`, `llama.cpp`, `OpenAI-compatible`
- `Markdown`, `HTML`, `PDF`, `Docker`, `docker-compose`, `Makefile`,
  `goreleaser`, `sqlc`
