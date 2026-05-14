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
acceptance criteria. Phases 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, and 11 are
complete from the repository perspective, so the next implementation focus is
Phase 12: LLM Integration. Later phases can be inspected for context, but
implementation should not skip ahead unless a Phase 12 task explicitly depends
on later-phase context.

## Current Baseline

The current repo is not greenfield. These items are valuable baseline work and
must be carried forward:

- **Foundation:** Buildable Go module and CLI entrypoint with `scan`, `serve`,
  `sessions`, `plugins`, `report`, and `version` command surfaces.
- **Models and persistence:** Canonical model structs for sessions, targets,
  findings, CVEs, tool runs, attack vectors, report metadata, LLM analyses, and
  plugin records, plus per-session SQLite migrations and typed store methods.
- **Session store:** Per-session SQLite persistence in `.nox/sessions`, with
  create/list/show/delete support.
- **Scope safety:** Scope checker for hosts, URLs, and CIDRs.
- **Adapters:** Adapter interface, registry, plugin JSON contract, subprocess
  helper, built-in `http-probe`, built-in `security-headers`, and optional
  recon adapters for `subfinder`, `dnsx`, `naabu`, `httpx`, `whois`,
  `waybackurls`, `crt.sh`, plus fingerprinting adapters for `whatweb`,
  `nuclei` technology templates, `testssl.sh`, GraphQL introspection,
  OpenAPI/Swagger discovery, `wpscan`, `droopescan`, and enumeration adapters
  for `ffuf`, `arjun`, `linkfinder`, `gitleaks`, JavaScript secret scanning,
  CORS checks, scoped cloud bucket checks, plus vulnerability adapters for
  `nuclei` vulnerability templates, `sqlmap`, `dalfox`, SSRFmap, `jwt_tool`,
  OAuth, SSTI, XXE, `nikto`, and CVE intelligence correlation.
- **MVP external adapter slice:** Optional subprocess wrappers for `nmap`,
  `subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, `waybackurls`, `ffuf`,
  `whatweb`, `nuclei`, `testssl.sh`, `wpscan`, `droopescan`, `arjun`,
  `linkfinder`, `gitleaks`, `sqlmap`, and `dalfox`, plus HTTP-based
  GraphQL/OpenAPI/CORS/cloud bucket/OAuth/SSTI/XXE checks, JavaScript secret
  scanning, and a passive `crt.sh` HTTP adapter that is registered but not run
  by default. This is a useful MVP slice across spec reconnaissance,
  fingerprinting, enumeration, and vulnerability scanning. It is not a
  replacement for every future spec adapter.
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

**Status:** Implemented  
**Spec sections covered:** 3.4, 6

### Existing Baseline

- SQLite is the default database via `modernc.org/sqlite`.
- The repo stores one database file per engagement/session.
- Initial migration creates core session, target, finding, and tool run tables.
- Store methods support create/list/show/delete sessions, targets, findings,
  tool runs, stats, counts, and status updates.
- Ordered embedded migrations now apply incrementally and record each applied
  version in `schema_migrations`.
- Phase 2 persistence covers HTTP evidence, technologies, CVE matches, attack
  vectors, LLM analyses, and plugin records.
- Finding reads round-trip nested HTTP evidence and CVE matches.
- Target reads round-trip detected technologies.
- Attack vectors round-trip ordered steps and prerequisite finding IDs as
  structured JSON.
- LLM analyses round-trip messages and tool-call traces as structured JSON.
- Plugin records support upsert, list, and delete.

### Remaining Work

- None for Phase 2. API endpoints, CLI commands, adapter production of
  technologies, CVE correlation, attack-vector generation, LLM client behavior,
  and reporting are handled by later phases.

### Spec Alignment Follow-ups

- Keep current per-session SQLite path and existing databases compatible.
- Add future migrations incrementally instead of replacing earlier schemas.
- Continue using the handwritten store until sqlc conversion is justified.
- Keep optional PostgreSQL support deferred as a later team-deployment feature.

### Acceptance Criteria

- New sessions are stored as complete engagement databases.
- All scanner evidence, normalized findings, technologies, CVEs, attack vectors,
  and LLM conversations can be persisted and reloaded.
- Existing API and CLI session commands continue to work with migrated DBs.
- Tests verify required tables, upgrades from `001_initial`, and representative
  insert/list flows.

---

## Phase 3: Scope Validation And Session Lifecycle

**Status:** Implemented  
**Spec sections covered:** 2, 5.3, 16, 17, 18

### Existing Baseline

- Scope checker supports URLs, hosts, wildcard hosts, IPs, and CIDRs.
- Session creation validates the initial target.
- Built-in and external MVP adapters validate target host scope before network
  requests or subprocess scanner invocation.
- Session statuses include pending, running, completed, failed, and cancelled.
- Running API scans can be cancelled with `POST /api/scan/{id}/stop`.
- Cancellation propagates through adapter contexts and sets session status to
  cancelled.
- Adapter failures are recorded as failed `tool_runs` without failing the
  session.
- WebSocket scan events remain available at `GET /api/scan/{id}/events`, with
  the spec-compatible alias `WS /ws/scan/{id}`.
- Tests cover no-network scope rejection for HTTP adapters, non-fatal adapter
  failures, cancellation status transitions, and the spec WebSocket route.

### Remaining Work

- None for Phase 3. Configuration-backed defaults, selected tools, rate limits,
  concurrency caps, and broader structured logging are handled by later phases.

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

**Status:** Implemented  
**Spec sections covered:** 3.5, 7

### Existing Baseline

- Adapter interface exists with ID, name, phase, dependencies, `ShouldRun`, and
  `Run`.
- Global registry exists.
- Subprocess JSON plugin contract exists.
- Direct subprocess command helper exists for scanner CLIs.
- MVP external adapters record `tool_runs` for missing binaries, timeouts,
  non-zero exits, and parser-normalized findings.
- CLI plugin management supports `nox plugins list` and
  `nox plugins install --session <id> <path>`.
- Configured plugin metadata persists in the per-session plugin store.
- Enabled configured plugins load into the scan runner alongside built-in
  adapters.
- Configured plugins invoke the subprocess JSON contract and normalize returned
  findings, technologies, and new targets into session models.
- Missing or failing plugin binaries produce failed persisted `tool_runs`
  without failing the scan.

### Remaining Work

- Plugin directory loading, config-backed tool path overrides, expanded adapter
  authoring docs, and broader fixture layout are deferred to configuration and
  scanner-expansion phases.

### Spec Alignment Follow-ups

- Keep current subprocess JSON contract as the initial plugin mechanism.
- Treat `hashicorp/go-plugin` or gRPC plugins as future optimization only.

### Acceptance Criteria

- `nox plugins list` reports built-in adapters and configured plugins.
- Plugin binaries can be configured and invoked through the adapter contract.
- Missing or failing plugin binaries produce persisted `tool_runs`.
- Adapter tests prove output normalization is deterministic.

---

## Phase 5: DAG Scheduler And Live Scan Events

**Status:** Implemented  
**Spec sections covered:** 8, 9, 13 WebSocket event format

### Existing Baseline

- Runner orders adapters by dependencies.
- Scan lifecycle events exist for queued, running, tool started, tool completed,
  finding found, failed, and completed states.
- API exposes `GET /api/scan/{id}/events` as the current WebSocket endpoint.
- Dashboard consumes live events and retains REST polling fallback.
- Runner now builds dependency levels from adapter `DependsOn()` declarations.
- Same-level adapters run concurrently subject to global and per-tool
  semaphores.
- Runner options expose testable global concurrency, per-tool concurrency,
  per-tool delay, and per-tool timeout controls.
- Adapter inputs receive accumulated prior findings and technologies from
  earlier dependency levels.
- Phase-level events and tool-error events are emitted while preserving existing
  dashboard-compatible event types.
- Cancellation emits a dedicated cancelled event and retains Phase 3 cancelled
  status semantics.

### Remaining Work

- CVE correlator and attack vector engine triggers remain deferred to Phases 10
  and 11, after the scanner pipeline produces richer technology and finding
  data.

### Spec Alignment Follow-ups

- Do not discard current runner; continue evolving it incrementally as scanner
  phases become richer.
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

**Status:** Implemented
**Spec sections covered:** 8 Phase 1, 22 step 6

### Existing Baseline

- Built-in `http-probe` provides a lightweight safe HTTP probe.
- MVP subprocess `nmap` records open-port findings when available.
- Optional `subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, and `waybackurls`
  adapters are registered and included in the default safe runner.
- Optional `crt.sh` HTTP recon adapter is registered and available, but is not
  run by default so passive third-party lookups remain an explicit choice.
- Recon adapters validate scope before network execution.
- Missing external binaries are captured as failed `tool_runs` instead of
  failing the scan.
- Recon output is normalized into new targets, open-port findings, live HTTP
  service findings, technologies, archived URL findings, WHOIS metadata, and
  raw tool evidence.
- Parser tests cover host normalization, open ports, HTTPX JSON output,
  technologies, WHOIS output, URL discovery, and crt.sh target normalization.

### Remaining Work

- None for the repository-level Phase 6 acceptance criteria.

### Spec Alignment Follow-ups

- Do not remove current `http-probe`; it can remain as a safe built-in probe
  beside or before full `httpx`.
- Keep current subprocess `nmap` useful until Go-wrapper parity is implemented.
- Keep current subprocess ProjectDiscovery tools useful until Go-library
  migration is needed for richer streaming output, structured config, or
  distribution constraints.
- Add configuration controls before enabling passive third-party sources such
  as `crt.sh` by default.
- Add deeper service/version parsing for `nmap` and `httpx` when later phases
  need stronger CVE matching inputs.

### Acceptance Criteria

- Recon phase builds an in-scope target map from the current target plus
  optional external recon output.
- New targets are persisted and available to later phases.
- Missing external recon tools degrade gracefully through persisted failed
  `tool_runs`.
- Parser tests cover normalization for each new recon output family.

---

## Phase 7: Fingerprinting Adapters

**Status:** Implemented
**Spec sections covered:** 8 Phase 2

### Existing Baseline

- `security-headers` adapter identifies missing CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, and Referrer-Policy.
- Dashboard and API expose these normalized findings.
- Phase 6 `httpx` can already persist discovered web technologies when the
  external binary is installed.
- Optional `whatweb` subprocess adapter parses detected web technologies and
  versions.
- Optional `nuclei-tech` subprocess adapter runs technology-tagged templates and
  persists technology matches plus normalized informational findings.
- Optional `testssl.sh` subprocess adapter parses TLS/certificate findings.
- Built-in GraphQL introspection check probes `/graphql` and reports exposed
  schema introspection.
- Built-in OpenAPI/Swagger discovery checks common API documentation paths and
  reports exposed docs.
- Optional `wpscan` subprocess adapter records WordPress core, theme, and plugin
  technology versions and vulnerability metadata.
- Optional `droopescan` subprocess adapter records CMS technology detections and
  vulnerability metadata.
- Missing external fingerprinting binaries degrade gracefully through persisted
  failed `tool_runs`.
- Parser tests cover technology, TLS, GraphQL, OpenAPI/Swagger, WordPress, and
  CMS fingerprint normalization.

### Remaining Work

- None for the repository-level Phase 7 acceptance criteria.

### Spec Alignment Follow-ups

- Keep `security-headers` as the initial built-in fingerprinting adapter.
- Reuse the existing technologies table/store methods for every fingerprinting
  adapter that emits product/version data.
- Keep subprocess `nuclei` technology templates useful until a Go-library
  migration is needed for richer structured output or distribution constraints.
- Extend `droopescan` invocation/configuration when CMS-specific selection is
  configurable.
- Phase 10 will consume persisted technology names/versions for CVE
  correlation.

### Acceptance Criteria

- Live HTTP/S targets receive fingerprinting coverage.
- Technologies with versions are stored for CVE correlation.
- TLS, CMS, GraphQL, OpenAPI/Swagger, and security header findings normalize
  into the shared finding schema.

---

## Phase 8: Enumeration Adapters

**Status:** Implemented
**Spec sections covered:** 8 Phase 3

### Existing Baseline

- MVP `ffuf` subprocess adapter discovers web paths when installed and a common
  wordlist exists.
- Optional `arjun` subprocess adapter records hidden HTTP parameter findings.
- Optional `linkfinder` subprocess adapter records JavaScript endpoint findings.
- Optional `gitleaks` subprocess adapter records exposed secret findings.
- Built-in JavaScript secret scan fetches the page and same-origin script files
  and records matched secret patterns with raw evidence.
- Built-in CORS check records wildcard/reflected-origin misconfigurations and
  includes attack-vector tags such as `cors-wildcard-credentials`.
- Built-in scoped cloud bucket check records public S3/GCS-style bucket
  exposure only when the scanned target is itself the scoped bucket endpoint.
- Missing external enumeration binaries degrade gracefully through persisted
  failed `tool_runs`.
- Parser tests cover hidden parameters, JavaScript endpoints, gitleaks output,
  JavaScript secret patterns, CORS tags, and cloud bucket exposure.

### Remaining Work

- None for the repository-level Phase 8 acceptance criteria.

### Spec Alignment Follow-ups

- Current `ffuf` adapter is an MVP slice and should be extended with configured
  wordlists, response filtering, and better path classification.
- Add config-driven wordlists, per-tool rate limits, and response filters in
  Phase 14.
- Add optional `feroxbuster` or `trufflehog` alternatives if tool availability
  or output quality is better than the current subprocess choices.
- Feed persisted hidden parameter and endpoint findings into Phase 9
  vulnerability-scanning target selection.

### Acceptance Criteria

- Enumeration produces persisted findings and, where useful, discovered URLs or
  target metadata for later phases.
- Secrets and exposed storage checks preserve raw evidence.
- CORS findings include tags needed by attack vector rules.

---

## Phase 9: Vulnerability Scanning Adapters

**Status:** Implemented
**Spec sections covered:** 8 Phase 4

### Existing Baseline

- MVP `sqlmap` subprocess adapter runs against query URLs.
- MVP `dalfox` subprocess adapter runs against query URLs.
- Both validate scope and persist `tool_runs`.
- Optional `nuclei-vuln` subprocess adapter runs vulnerability templates and
  normalizes matched template findings.
- Optional SSRFmap subprocess adapter uses query/hidden-parameter targets from
  Phase 8.
- Optional `jwt_tool` subprocess adapter runs when a JWT-like token is present
  in target input or prior evidence.
- Built-in OAuth check probes untrusted `redirect_uri` behavior on OAuth-like
  surfaces.
- Built-in SSTI check sends a bounded arithmetic template probe against query or
  hidden-parameter targets.
- Built-in XXE fuzz check sends a bounded XML payload and only reports direct
  response indicators.
- Optional `nikto` subprocess adapter parses JSON or text web-server findings.
- Existing `sqlmap` and `dalfox` wrappers now use Phase 8 hidden-parameter
  discoveries when the initial target URL has no query string.
- Parser tests cover nuclei vulnerability output, SSRFmap, JWT, OAuth, SSTI,
  XXE, Nikto, and hidden-parameter target handoff.

### Remaining Work

- None for the repository-level Phase 9 acceptance criteria.

### Spec Alignment Follow-ups

- Keep current `sqlmap` and `dalfox` wrappers while adding deeper multi-target
  scheduling when the runner supports multiple tool runs per adapter.
- Keep subprocess `nuclei` vulnerability templates useful until a Go-library
  migration is needed for richer streaming output or distribution constraints.
- Add configuration for higher-risk payload sets, out-of-band callbacks, and
  stricter per-tool rate limits before enabling more aggressive modes.
- Phase 11 attack vectors should consume vulnerability tags from this phase.

### Acceptance Criteria

- Vulnerability scanning only runs in appropriate scan modes.
- Dangerous checks are bounded by scope, rate limits, and timeout settings.
- Confirmed vulnerability findings support attack vector and report generation.

---

## Phase 10: CVE Intelligence

**Status:** Implemented
**Spec sections covered:** 5.4, 11, 16 CVE settings

### Existing Baseline

- CVE model exists.
- CVE match persistence exists.
- `internal/cve` package provides deterministic correlation, in-memory cache,
  offline JSON source support, embedded advisory fallback data, and HTTP client
  scaffolding for NVD, OSV.dev, CIRCL, vulners.com, and GitHub Security
  Advisories.
- `NOX_CVE_OFFLINE_PATH` enables local offline advisory data.
- `NOX_CVE_ENABLE_REMOTE=true` opts in to remote CVE clients; default operation
  remains local/offline-friendly.
- Runner invokes CVE correlation after scan phases complete and before final
  session counts/status are updated.
- Technology/version matches are persisted as `cve_matches`.
- CVE identifiers observed in finding evidence are persisted as finding-linked
  `cve_matches`.
- Exploitable CVEs with CVSS score >= 7.0 create draft attack vectors.
- Unit tests cover cache reuse, offline source matching, technology matching,
  finding evidence matching, CVE ID extraction, and draft vector generation.

### Remaining Work

- None for the repository-level Phase 10 acceptance criteria.

### Spec Alignment Follow-ups

- Technology persistence from fingerprinting is a prerequisite for full CVE
  correlation.
- Expand remote client parsers beyond NVD as API credentials and rate-limit
  behavior are configured in Phase 14.
- Add an Exploit-DB CSV source when a local mirror path is specified.
- Persist CVE cache to disk if repeated process restarts need cache reuse.
- Phase 11 should merge CVE-generated draft vectors with deterministic attack
  vector rules.

### Acceptance Criteria

- CVE correlation runs after scan phases.
- CVE matches are linked to technologies or findings.
- CVE cache works without repeated remote calls.
- Offline mode works with local data sources.

---

## Phase 11: Attack Vector Engine

**Status:** Implemented
**Spec sections covered:** 5.5, 12

### Existing Baseline

- Attack vector models and persistence exist.
- Deterministic rule engine supports conditions by tool ID, finding type,
  minimum severity, URL substring, tag substring, and parameter presence.
- Rule-generated vectors include OWASP category, severity, confidence,
  narrative, prerequisite finding IDs, ordered steps, and suggested tools.
- Runner invokes the attack vector engine after CVE correlation and skips
  duplicate vectors by title/prerequisite set.
- Default rules cover:
  - reflected XSS with missing CSP
  - SSRF to cloud metadata
  - weak JWT secret
  - unauthenticated SQL injection
  - exposed admin panel with weak/default auth indicators
  - CORS wildcard credentials
- CVE matches with exploit availability and score >= 7 also produce vectors.
- LLM review fields remain separate and default to unreviewed.
- Unit tests cover all default rules, missing prerequisite behavior, and CVE
  vector generation.

### Remaining Work

- None for the repository-level Phase 11 acceptance criteria.

### Spec Alignment Follow-ups

- Fix rule references to current tool IDs where needed, while preserving spec
  semantics.
- Ensure findings include tags required by attack rules.
- Phase 12 should add LLM annotation/review only after deterministic vectors are
  generated, without overwriting rule facts.
- Phase 13 and Phase 16 should expose vectors through API and UI surfaces.

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
| 3.4 Database | Phase 2 | Implemented | Per-session SQLite, ordered migrations, and store methods cover Phase 2 persistence; optional Postgres remains later. |
| 3.5 Plugin System | Phase 4 | Implemented | JSON contract, CLI install/list, plugin persistence, configured plugin loading, and failed tool-run degradation exist. |
| 3.6 Packaging | Phase 17 | Partial | Docker, Compose, Makefile, CI build, and snapshot release exist; deeper release hardening pending. |
| 4. Project Structure | All phases | Partial | Current structure is close but not complete. |
| 5. Core Data Models | Phase 1 | Implemented | Canonical models, report metadata models, additive CVE version fields, and serialization/validation tests exist. |
| 6. Database Schema | Phase 2 | Implemented | Schema covers sessions, targets, findings, evidence, technologies, CVEs, vectors, tool runs, LLM analyses, plugins, and migrations. |
| 7. Tool Adapter System | Phase 4 | Implemented | Built-in registry and configured subprocess plugin adapters coexist; broader ecosystem docs remain later. |
| 8. Tool Pipeline | Phases 6-9 | Implemented | Recon, fingerprinting, enumeration, and vulnerability-scanning adapter slices now cover Phases 6-9; deeper Go-library migrations and richer targeting remain follow-ups. |
| 9. DAG Engine | Phase 5 | Implemented | Dependency levels, same-level concurrency, semaphores, timeout/delay controls, prior-result propagation, and phase events exist. |
| 10. LLM Integration | Phase 12 | Pending | Session fields/placeholders exist only. |
| 11. CVE Intelligence | Phase 10 | Implemented | Correlator, offline source, cache, NVD client parser, evidence CVE extraction, persisted matches, and draft vectors exist; richer remote source parsers remain follow-ups. |
| 12. Attack Vector Engine | Phase 11 | Implemented | Deterministic rule engine, default rules, scoring, steps, persistence integration, CVE vector merging, and rule tests exist; LLM annotation remains Phase 12. |
| 13. REST API Surface | Phase 13 | Partial | Core read/start endpoints exist; stop/vector/CVE/LLM/report/auth pending. |
| 14. CLI Commands | Phase 14 | Partial | Core commands exist; full flags/config/LLM/report pending. |
| 15. Web UI Pages | Phase 16 | Partial | Dashboard exists; full session pages pending. |
| 16. Configuration File | Phase 14 | Pending | Config system pending. |
| 17. Scope Validation | Phase 3 | Implemented | Checker, adapter boundary tests, cancellation, and lifecycle status coverage exist; config integration remains later. |
| 18. Error Handling & Logging | Phases 3, 4, 5 | Partial | Tool failures persist without failing scans; broader structured logging/config pending. |
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
