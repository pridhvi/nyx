# Nyx Implementation Plan

This plan is the execution roadmap for the canonical product specification in
`docs/nyx-project-spec.md`. It intentionally preserves the current MVP work and
builds on top of it. Existing code should be extended, not discarded, unless a
specific implementation is proven incompatible with the spec.

## Planning Rules

- `docs/nyx-project-spec.md` is the source of truth for product behavior,
  architecture, API surface, data models, scanner coverage, UI pages, packaging,
  and safety expectations.
- `README.md`, `AGENTS.md`, and this plan must be updated after every major
  implementation change.
- Scope validation is a hard security boundary. Every network request and every
  subprocess scanner invocation must validate scope first.
- Evidence is first-class data. Store full tool stdout/stderr in session
  sidecar logs, keep HTTP request/response evidence in SQLite, and retain
  normalized output where the schema supports it.
- All scanner output must normalize into `internal/models.Finding` or one of the
  related canonical models before analysis.
- External tools are optional. Missing binaries, unavailable wordlists,
  subprocess timeouts, and non-zero exits are recorded as `tool_runs`; they
  should not prevent the rest of a scan from continuing.
- Authenticated subprocess scanners must not expose auth secrets in persisted
  tool-run args or live process argv when the scanner supports request/config
  files for auth material.
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

The implementation roadmap is complete from the repository perspective. Future
work should focus on hardening, richer fixtures, deeper UI interactions,
scanner-specific improvements, and benchmark-driven scanner depth rather than
adding new roadmap phases. The current depth plan is
`docs/benchmark-driven-scanner-depth.md`, which uses DVWA, OWASP Juice Shop,
crAPI, OWASP Benchmark, DVGA, WebGoat, and NodeGoat as repeatable targets for
generic authenticated scanning, route-seeding, validation, authorization,
API/GraphQL coverage, and business-logic-assist capabilities. App-specific
setup and expected mappings belong in benchmark profiles only; scanner adapters
must remain target-agnostic.

Current benchmark-depth implementation includes the opt-in benchmark harness,
benchmark profile/expected mapping files for DVWA, Juice Shop, crAPI, OWASP
Benchmark, DVGA, WebGoat, and NodeGoat, benchmark-only target preflight setup
for DVWA token-backed database initialization, low-security mode, and Juice Shop
user registration, strict `all_match` coverage mappings
where tool plus route/title evidence must line up, CLI/API/UI route seed inputs,
static auth header/cookie scan context, generic form and JSON login auth
profiles with CSRF/token extraction and validation requests, bounded
validation/re-login refresh during long scans, `auth_status` lifecycle events
for validation and refresh outcomes, redacted session JSON/tool-run arguments
for auth material, auth-aware safe validators including file inclusion and weak
session checks, benchmark-safe command injection validation, stored XSS
read-back validation, browser-backed DOM XSS marker validation for seeded
hash/search routes with multiple browser payload shapes and JavaScript dialog
marker observation, seeded external redirect validation, CSP bypass
human-assist review, CAPTCHA-protected sensitive-workflow review, CAPTCHA
answer exposure checks, built-in JWT claim review for missing expiration and
sensitive hash-bearing claims without persisting token values, strict
credential validation gated by
intentionally-vulnerable/non-production profile flags, phase-ordered DAG
scheduling with registered adapter order preserved inside a phase and slow
external vulnerability scanners ordered after benchmark-safe built-in
validators, XXE marker validation for raw XML and multipart upload-like routes,
observability-assist review for seeded metrics/debug/health/monitoring surfaces,
deserialization-assist review for seeded upload/import/restore/object-state surfaces,
structured human-assist response context with redacted excerpts and relevant
form metadata where available,
first adapter consumers for built-in HTTP checks plus `ffuf`, `sqlmap`, and
`dalfox`, and benchmark summary gates that fail the strict release-gate
benchmark commands if DVWA drops below 14 covered items, Juice Shop drops below
15 covered items, crAPI drops below 12 covered categories, or any strict-gate
benchmark tool run exits nonzero unless an explicit local override is set. crAPI
has an authenticated benchmark profile, route seeds, strict category mappings,
and a measured Linux VM baseline of 12/12 covered categories after generic
API-depth improvements. OWASP Benchmark, DVGA, WebGoat, and NodeGoat start as
baseline integrations with target startup, route seeds, artifact generation, and
no minimum coverage gate until accepted mappings are established.
The latest Linux VM acceptance pass, run on 2026-05-28 against commit
`a41272c`, passed strict Linux tool smoke, `NYX_RUN_LINUX_FULL=1 make
linux-full-smoke`, DVWA at 14/14 with 42 findings, Juice Shop at 15/15 with 28
findings, and LM Studio-backed LLM CLI/UI smoke against real persisted DVWA
session data.

## Current Baseline

The current repo is not greenfield. Sessions use `<session-id>/session.db` with
tool run sidecar logs in `<session-id>/runs/`; `nyx scan --lean` deletes those
logs after normalization, and `nyx sessions export` packages the directory.
Cross-session monitor state uses `<state-dir>/nyx-state.db` for recurring
monitor configs, monitor runs, and persisted attack-surface changes.
Sessions preserve `mode` for scan aggressiveness and use `workload_mode` for
`dynamic`, `static`, and `combined` workloads. These items are valuable baseline
work and must be carried forward:

- **Foundation:** Buildable Go module at `github.com/pridhvi/nyx` and CLI
  entrypoint with `scan`, `audit`, `serve`, `sessions`, `plugins`, `report`,
  and `version` command surfaces.
- **Models and persistence:** Canonical model structs for sessions, targets,
  findings, source findings, graph edges, CVEs, tool runs, attack vectors,
  report metadata, LLM analyses, and plugin records, plus per-session SQLite
  migrations and typed store methods.
- **Session store:** Per-session SQLite persistence defaults to the absolute
  state path `$HOME/.nyx/sessions`, with create/list/show/delete support and
  config-relative resolution for explicit relative paths.
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
- **Runner:** Dependency-ordered runner with persisted tool runs, normalized
  findings, global plugin loading, cancellation, cooperative pause/resume before
  starting the next tool, and a scanner-owned HTTP client that keeps redirects
  and direct dials inside session scope while ignoring ambient proxy environment
  variables unless a scan explicitly configures `proxy_url`. This should keep
  evolving incrementally into the full spec DAG scheduler instead of being
  thrown away.
- **Continuous monitoring:** `nyx monitor` and `/api/monitor/*` manage
  host-privileged recurring scan configs, immediate monitor runs, scheduler
  registration during `nyx serve`, one-run catch-up for overdue schedules on
  startup, baseline comparison, HTTPS-only guarded Slack/Discord webhook
  notification dispatch that rejects local/private/metadata destinations, and
  `surface_changes` persistence for target, technology, and finding drift.
- **Power-feature modules:** Payload generation now supports optional
  LLM-assisted payloads with deterministic fallback and safe marker validation;
  credential checks are lockout-aware, paced, scope-checked, and redacted by
  default; OSINT records include provider status for GitHub/Shodan/passive DNS
  configuration; AD/internal-network records include safe enum, relay-risk, and
  Kerberoast request recording without cracking; PoC records can include safe
  validation and callback correlation while re-checking persisted finding URLs
  and redirects against session scope before marker requests; callback event
  bodies are redacted before API/UI display; Burp supports session-scoped XML
  import/export plus loopback default REST status, scope push, and issue pull
  helpers with explicit allowlisting for remote/private REST hosts and
  redirect/connect-time DNS guardrails. All modules have additive
  models, persistence, API/CLI access, report sections, integration smoke, and
  consolidated UI visibility. Active behavior remains explicit, conservative,
  scope-checked, and API-key-gated through the API.
- **Audit and source-aware mode:** Static extractors cover Python,
  JavaScript/TypeScript, Go, PHP, Ruby, and Java for routes, parameters, SQL
  sinks, file uploads, auth middleware, secrets, SSRF sinks, deserialization
  sinks, and unprotected routes. `nyx audit` runs built-in and optional
  `audit/<tool>` adapters with `.nyx-audit-ignore` suppression, sidecar logs,
  optional LLM triage/dataflow/narrative passes, and terminal/JSON/SARIF/HTML/MD
  output. `nyx scan --source` runs static-only without a target and combined
  source-aware mode with a target; combined orchestration runs source/audit
  first for SQLite reliability, then dynamic adapters consume persisted source
  hints, then a shared correlation phase generates CVEs, graph edges, attack
  vectors, dynamic confirmations, and optional LLM review. Static parser
  coverage is tool-specific for the registered audit tools with a generic JSON
  fallback for future adapter shapes.
- **LLM analyst:** Optional local-first OpenAI-compatible client implemented
  through `github.com/sashabaranov/go-openai`, structured scan context builder,
  constrained LLM tools, evidence truncation, and persisted
  conversation/tool-call audit trails.
- **API:** Health, tools, sessions, targets, findings, source findings, tool
  runs, stats, scan start/status/pause/resume/stop, vectors, attack graph edges,
  CVEs, reports, LLM history/analysis/chat, session deletion, scan profiles,
  monitor configs/runs/surface changes, payloads, credentials, OSINT, provider
  statuses, AD, block events, callbacks, PoC results, Burp XML import/export,
  Burp REST helpers, constrained source-directory browsing, and config callbacks,
  API-key-protected global plugins, API-key-protected LLM model probing,
  API-key enforcement for non-loopback serving and host-privileged API
  operations, and scan lifecycle
  WebSocket event stream. Scan start accepts legacy `target`, multi-target
  `targets`, `source_path`, and combined target+source requests.
- **WebSocket progress:** Current endpoint is `GET /api/scan/{id}/events` with
  bounded event replay. The spec route `WS /ws/scan/{id}` is also available as
  a compatibility alias.
- **Reporting and UI:** Markdown/HTML/SARIF/paginated-PDF report generation,
  CLI/API/UI report access, and React/Vite dark-default operator console with a
  Nyx logo/favicon, dashboard controls, readable live progress rows, recent
  events, and live terminal feed, responsive mobile topbar actions,
  multi-target scan and source scan builder with server-side source folder
  browsing, compact scrollable tool groups, a non-overlapping launch review,
  per-tool configuration modals, profile import/export, Recharts severity chart
  with theme-aware surfaces, a React Flow/dagre Attack Paths workspace, grouped
  source finding summaries with filters and context expansion, sortable
  finding/CVE tables with static/dynamic/status filters, empty finding states,
  mobile finding cards, bulk finding workflow, finding evidence/edit workflow,
  API-key-guided global plugin registration, checkbox-driven monitor
  config/run/change review, responsive session-aware tool inventory cards,
  polished stdout/stderr log drawers, LLM model probing, settings health panels
  with collapsible raw config, shell-level skeletons/retryable API error banners,
  global search, keyboard shortcuts, toast notifications, manual session
  comparison, first-run guidance, and report pages backed by real API data with
  explicit no-session/loading/error/empty states. Reports include source findings,
  suppressed findings, tool coverage, dependency CVEs, and cross-confirmed
  static/dynamic evidence. Built assets are embedded into
  `internal/api/web/dist`.
- **Verification:** `go test ./...` and `npm run build` pass for the current
  working set.

---

## Phase 0: Repository, Safety, And Toolchain Foundation

**Status:** Implemented
**Spec sections covered:** 1, 2, 3, 20, 21, 22, 23

### Existing Baseline

- Go module path is `github.com/pridhvi/nyx`.
- CLI exists.
- React/Vite frontend exists and builds into embedded assets.
- Repository guidance exists in `AGENTS.md`.
- README describes local-first purpose and safety boundary.
- README and CLI help include authorized-testing legal guidance.
- Makefile targets exist for build, dev, test, opt-in integration smoke, tool
  version smoke, lint, web, sqlc placeholder, migration placeholder, cleanup,
  and release snapshot.
- Dockerfile and docker-compose exist for Nyx plus Ollama services.
- GoReleaser snapshot configuration exists for embedded-frontend single-binary
  release artifacts.
- GitHub Actions CI runs Makefile test/web/build workflows, Docker image build,
  Compose config validation, and GoReleaser snapshot release.
- Local Docker validation now covers image build, `nyx version`, bundled scanner
  version checks, CLI help, docker-compose startup, `/api/health`, and
  `/api/tools` with writable session storage.

### Remaining Work

- Keep `sqlc` and PostgreSQL as explicitly deferred architecture tracks unless
  query complexity or team-deployment requirements justify them.
- Expand Docker-bundled tool coverage only when a scanner has stable packaging
  and deterministic smoke behavior.

### Spec Alignment Follow-ups

- Do not remove current local development workflow while adding Docker and
  release tooling.
- Keep external tools optional outside the Docker image.
- Ensure all docs preserve the local-first, air-gap-capable design principles.

### Acceptance Criteria

- README and CLI visibly warn that Nyx is for authorized testing only.
- `make build`, `make test`, and `make web` work.
- `make security-scan` runs the production `gosec` policy with intentionally
  vulnerable fixtures excluded and intentional production findings justified
  inline.
- CI validates that the Docker image builds.
- CI validates Docker Compose configuration for Nyx and Ollama services.
- Local Docker smoke validation can start Nyx and Ollama and report API health
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
- CLI plugin management supports `nyx plugins list` and
  `nyx plugins install --name <name> --phase <phase> <path>`.
- Configured plugin metadata persists in the global plugin registry under the
  Nyx state directory. Legacy session plugin rows remain readable for old
  sessions.
- Configured plugin records store a SHA-256 digest at registration, plugin
  uploads return the computed digest, and enabled plugin execution rechecks the
  digest before spawning the subprocess.
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

- `nyx plugins list` reports built-in adapters and configured plugins.
- Plugin binaries can be configured and invoked through the adapter contract.
- Plugin binary digest mismatches produce failed persisted `tool_runs` before
  execution.
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
- Keep current subprocess ProjectDiscovery tools as the supported v1 path.
  Native Go-library migration is explicitly deferred because it increases
  dependency weight, in-process resource risk, upstream API instability, and
  maintenance burden. If revisited, evaluate `httpx` first and keep `nuclei`
  and `naabu` deferred until the pattern proves stable.
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
- Built-in JWT review runs when a JWT-like token is present in authenticated
  scan context, target input, or prior evidence; it checks for missing
  expiration and sensitive hash/secret claim paths before optionally invoking
  `jwt_tool` as an external supplement.
- Built-in OAuth check probes untrusted `redirect_uri` behavior on OAuth-like
  surfaces.
- Built-in reflected XSS validator mutates browser-facing seeded/query/hidden
  parameters with a unique marker and only reports confirmed reflection.
- Built-in DOM XSS validator mutates seeded query/hash routes with several
  browser payload shapes and confirms either DOM marker state or marker-bearing
  JavaScript dialog execution before slow external vulnerability tools run.
- Built-in open redirect validator mutates seeded redirect-like query
  parameters with a controlled external marker and never follows the redirect.
- Built-in SQL injection validator mutates seeded/query/hidden parameters with
  bounded boolean predicates and a quote canary; boolean differentials are
  confirmed, while SQL error indicators, including SQLite error markers, are
  suspected findings.
- Built-in file inclusion validator mutates seeded file/path query parameters
  with bounded local hosts-file marker payloads and confirms only when the
  baseline response lacks those markers.
- Built-in command injection validator submits harmless echo-marker payloads
  only when the target profile or tool parameters mark the target intentionally
  vulnerable and non-production; reflected payloads do not count as confirmed
  execution.
- Built-in stored XSS validator submits a harmless unique marker to seeded
  forms only when the target profile or tool parameters mark the target
  intentionally vulnerable and non-production, then confirms only on a later
  authenticated read-back request.
- Built-in brute-force validator submits explicitly configured benchmark
  credentials with a total attempt budget clamped to 1-3, stops on lockout
  indicators, and redacts passwords from tool-run output and findings.
- Built-in upload validator submits a harmless text marker file to seeded upload
  routes and confirms only response echo or scoped retrieval of the marker.
- Built-in IDOR check tests seeded object identifier routes with adjacent-object
  mutation and optional secondary-identity replay; adjacent-object matches are
  suspected, secondary-identity replay can be confirmed.
- Built-in workflow-assist check reviews seeded high-value forms,
  business-control query parameters, CAPTCHA-protected sensitive forms, and
  CAPTCHA challenge responses that expose answers without submitting state
  changes; form/workflow output remains suspected human-assist evidence, while
  answer exposure can be confirmed from response content.
- Built-in observability-assist check reviews seeded metrics, logging, debug,
  health, monitoring, and verbose-error surfaces without asserting exploitation.
- Built-in deserialization-assist check reviews seeded upload, import, restore,
  serialized-object, YAML, pickle, and archive surfaces without submitting
  exploit payloads.
- Built-in CSRF check inspects seeded state-changing forms for missing token
  fields without submitting them.
- Built-in weak-session check samples seeded session-related routes for
  predictable cookie or body-token values with tight request bounds.
- Built-in SSTI check sends a bounded arithmetic template probe against query or
  hidden-parameter targets.
- Built-in XXE fuzz check now uses a non-exfiltrating internal XML entity marker
  against raw XML routes and multipart upload-like routes, and only reports
  direct marker resolution.
- Built-in CORS check records both simple and preflight response headers and
  flags reflected arbitrary origins even without credentials at lower severity.
- Optional `nikto` subprocess adapter parses JSON or text web-server findings.
- Existing `sqlmap` and `dalfox` wrappers now use Phase 8 hidden-parameter
  discoveries when the initial target URL has no query string.
- Parser and adapter tests cover nuclei vulnerability output, SSRFmap, JWT
  claim review and `jwt_tool` fallback behavior, OAuth, reflected XSS, open
  redirect, SQL injection validation, file inclusion validation, command
  injection safety gates, upload validation, IDOR checks, workflow-assist
  hints, CSRF form analysis, weak session sampling, CORS reflected-origin
  handling, SSTI, XXE, Nikto, and hidden-parameter target handoff.

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
- `NYX_CVE_OFFLINE_PATH` enables local offline advisory data.
- `NYX_CVE_ENABLE_REMOTE=true` opts in to remote CVE clients; default operation
  remains local/offline-friendly.
- Runner invokes CVE correlation after scan phases complete and before final
  session counts/status are updated.
- Technology/version matches are persisted as `cve_matches`.
- CVE identifiers observed in finding evidence are persisted as finding-linked
  `cve_matches`.
- Exploitable CVEs with CVSS score >= 7.0 create draft attack vectors.
- Unit tests cover cache reuse, offline source matching, Exploit-DB CSV mirror
  matching, technology matching, finding evidence matching, CVE ID extraction,
  and draft vector generation.

### Remaining Work

- None for the repository-level Phase 10 acceptance criteria.

### Spec Alignment Follow-ups

- Technology persistence from fingerprinting is a prerequisite for full CVE
  correlation.
- Continue expanding remote client parsers as API credentials and rate-limit
  behavior are configured in Phase 14.
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
- LLM review fields remain separate, default to unreviewed, and are annotated
  after successful LLM analysis.
- Unit tests cover all default rules, missing prerequisite behavior, and CVE
  vector generation.

### Remaining Work

- None for the repository-level Phase 11 acceptance criteria.

### Spec Alignment Follow-ups

- Fix rule references to current tool IDs where needed, while preserving spec
  semantics.
- Ensure findings include tags required by attack rules.
- Persisted LLM analysis runs only after deterministic vectors are generated,
  and annotates review notes without overwriting rule facts.
- Keep API and UI vector exposure aligned with the deterministic schema.

### Acceptance Criteria

- Rule tests cover each default attack vector rule.
- Generated vectors include steps, OWASP category, severity, confidence, and
  source findings.
- LLM review can annotate but not overwrite deterministic facts without trace.

---

## Phase 12: LLM Integration

**Status:** Implemented
**Spec sections covered:** 3.2 LLM dependency, 5.3 LLM session fields, 10

### Existing Baseline

- Session model includes LLM model/base URL fields.
- Placeholder UI page exists for LLM chat.
- LLM analysis persistence exists in the per-session database.

### Implemented Work

- Added `internal/llm` OpenAI-compatible chat client using
  `github.com/sashabaranov/go-openai` and supporting:
  - Ollama
  - LM Studio
  - llama.cpp OpenAI-compatible servers
  - OpenAI-compatible cloud endpoints when configured
- Added LLM config from session fields and environment:
  - provider
  - base URL
  - API key
  - model
  - max tokens
  - temperature
- Added structured context builder that summarizes:
  - session
  - targets
  - technologies
  - findings
  - CVE matches
  - attack vectors
  - stats
- Long raw evidence and HTTP request/response fields are truncated before
  being sent to an LLM.
- Added constrained tool definitions:
  - `request_scan`
  - `lookup_cve`
  - `search_cves_for_technology`
  - `get_session_findings`
- Added analyst loop with `go-openai` chat completion, streaming, and tool-call
  types plus visible tool-call audit trail.
- Persisted system/user/assistant/tool messages, tool-call arguments, tool
  results, model id, prompt summary, token totals, and creation time.
- Added spec-aligned system prompt that treats deterministic findings, CVEs,
  and attack-vector rules as authoritative.
- Added optional post-scan LLM analysis in the runner. It no-ops when no LLM is
  configured and does not fail scans when a configured LLM endpoint is
  unavailable.
- Added unit coverage for config, context truncation, tool constraints, analyst
  persistence, and tool-call audit trails.

### Remaining Work

- None for the repository-level Phase 12 acceptance criteria. API, CLI, report,
  and UI integration landed in Phases 13-16.

### Spec Alignment Follow-ups

- LLM integration must remain optional and local-first by default.
- Do not require cloud API keys for normal operation.
- LLM output annotates and explains; it must not overwrite deterministic
  findings, CVE matches, or attack vectors without trace.

### Acceptance Criteria

- LLM analysis can answer from structured session context.
- LLM tool calls are constrained by scope and recorded.
- Full-session analysis is persisted for later report and attack-narrative use.
- Operation degrades gracefully when no LLM is configured.

---

## Phase 13: REST API And Auth

**Status:** Implemented
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

### Implemented Work

- Added scan/session endpoints:
  - `POST /api/scan/{id}/stop`
  - `DELETE /api/sessions/{id}`
  - `GET /api/sessions/{id}/vectors`
  - `GET /api/sessions/{id}/cves`
  - `GET /api/sessions/{id}/report?format=html|pdf|md`
  - `POST /api/sessions/{id}/llm/chat`
  - `POST /api/sessions/{id}/llm/analyse`
  - `GET /api/sessions/{id}/llm/history`
  - `WS /ws/scan/{id}` compatibility alias
- Added filtering/pagination for findings:
  - severity
  - type
  - tool
  - page
  - limit
  - CVE/exploit filters where supported
- Added local API-key auth for API and WebSocket routes when configured, with
  API-key requirements for non-loopback binds, plugin management, API source
  scans, and LLM endpoint probing. Query-string API keys are rejected, failed
  auth uses exponential backoff keyed by client and credential fingerprint, the
  browser console uses opaque HttpOnly session cookies backed by memory-only
  12-hour server sessions with periodic pruning, cross-origin unsafe requests
  and WebSockets are blocked, and optional
  source-root/LLM-host allowlists can constrain privileged API inputs.
- Expanded health output:
  - DB readiness
  - LLM configuration status
  - registered tool count
  - session directory status

### Spec Alignment Follow-ups

- Keep current endpoints stable while adding spec endpoints.
- Keep current scan event endpoint as the canonical internal route unless route
  migration is intentionally scheduled.
- Add richer LLM reachability probing and per-tool availability checks in later
  hardening work.

### Acceptance Criteria

- API tests cover every spec endpoint.
- Auth can be disabled for localhost-only use and enabled for network access.
- Frontend can retrieve all data needed by spec UI pages.

---

## Phase 14: CLI And Configuration

**Status:** Implemented
**Spec sections covered:** 14, 16

### Existing Baseline

- CLI supports scan, serve, sessions, plugins, report, version.
- Scan supports target, name, mode, and out-of-scope.
- Serve supports host and port.
- Sessions supports list/show/delete/findings/runs.

### Implemented Work

- Added scan flags:
  - `--phases`
  - `--tools`
  - `--llm-model`
  - `--llm-url`
  - `--no-llm`
  - `--concurrency`
  - `--rate-limit`
- Added report flags:
  - `--format html|pdf|md`
  - `--output`
  - `--mode executive|technical`
- Added LLM commands:
  - `nyx llm chat <session-id>`
  - `nyx llm analyse <session-id>`
- Added config commands:
  - `nyx config init`
  - `nyx config show`
- Implemented config file at `~/.nyx/config.yaml` with:
  - LLM settings
  - database settings
  - server settings
  - default scan settings
  - CVE intelligence settings
  - tool paths
  - plugin directories
- Defined effective precedence:
  - CLI flags
  - environment variables
  - config file
  - defaults

### Spec Alignment Follow-ups

- Preserve current simple CLI behavior while expanding flags and config.
- Keep zero-config `nyx scan --target example.com` working.
- `--tools` and `--rate-limit` are accepted and config-backed; deeper
  scheduler/tool filtering semantics can be tightened with future scheduler
  refinements.

### Acceptance Criteria

- Config init writes a complete default config.
- CLI commands can override config.
- Tool paths, LLM settings, CVE settings, and scan defaults are usable by
  backend components.

---

## Phase 15: Reporting

**Status:** Implemented
**Spec sections covered:** 3.2 report dependencies, 15.6

### Implemented Work

- Added report generator package.
- Supports output formats:
  - Markdown
  - HTML
  - PDF
- Supports report modes:
  - executive
  - technical
- Includes report sections:
  - executive summary
  - scope and methodology
  - critical/high findings
  - medium/low findings summary
  - attack vectors with step-by-step chains
  - CVE matches with patch availability
  - remediation roadmap
  - raw tool output appendix
- Uses LLM-generated narrative only when LLM analysis exists; otherwise uses
  deterministic summaries.
- Added API and CLI report generation.
- Added report tests for Markdown, HTML, and PDF outputs.

### Spec Alignment Follow-ups

- Reporting depends on complete findings, evidence, CVEs, and attack vectors for
  full value, but basic Markdown/HTML can land earlier.
- PDF output is a basic dependency-free PDF generator; richer layout can be
  improved later without changing the CLI/API contract.

### Acceptance Criteria

- `nyx report <session-id> --format md|html|pdf` works.
- Report API returns requested format.
- Reports include persisted evidence and no fabricated conclusions.

---

## Phase 16: Web UI

**Status:** Implemented
**Spec sections covered:** 3.3, 15

### Implemented Work

- React/Vite app exists.
- Implemented dense midnight/violet operator shell with self-hosted Outfit and
  JetBrains Mono assets, command/build/triage/evidence/attack-path/analyst/export/system
  navigation, compact session command strip, status pills, responsive sidebar,
  and route recovery that drives command center, findings, tools, runs, graph,
  CVEs, LLM, and report pages.
- Implemented Scan Builder `/scan`:
  - progressive section rail for scope, profiles, phases, tools, advanced
    runtime/LLM controls, and launch
  - launch-readiness summary for scope, profile, phase, and runnable-tool state
  - sticky plain-English launch review with workload, targets, auth method,
    route seed count, phase count, selected tools, missing-tool warnings, and
    active-validator visibility
  - target, name, mode, and out-of-scope controls
  - server-side source repository picker constrained to configured/default
    source roots
  - built-in and API-backed saved scan profiles with a direct Load Profile
    action in the builder
  - route seed count and first-entry preview before launch
  - auth-profile JSON preflight feedback for parse errors, required login
    fields, scoped URLs, validation URLs, and CSRF/token declarations
  - phase cards with short descriptions
  - phase-aware tool selection with distinct states for installed built-in,
    installed optional, and missing subprocess/plugin tools
  - automatic dependency selection when dependent tools are enabled
  - start guard requiring at least one runnable selected tool
  - concurrency, per-tool concurrency, timeout, delay, and rate-limit controls
  - hover help for scan mode and runtime fields
  - hover help for seed routes, auth headers, cookie headers, auth profiles, and
    adaptive backoff
  - LLM base URL controls, connection probing, and discovered model selection
  - per-tool configuration modals backed by API metadata and backend validation
  - target textarea for multi-target scans and section-local required-field
    validation
  - custom scan profile JSON import/export
- Implemented Tools `/tools` and `/sessions/:id/tools`:
  - grouped readiness summary and table-first structured tool inventory
  - compact default inventory table with tool name, phase, version, status,
    binary path, and selected-tool detail panel
  - card view retained as a detail-oriented mode for install hints,
    dependencies, and descriptions
  - raw inventory table disclosure for troubleshooting
  - installed/missing status
  - configured binary path and version detection
  - phase, adapter kind, dependencies, install hints, and last run status
  - session-scoped last run status with explanatory copy for built-in and
    missing tool binary/version fields
  - global plugin registration, enable/disable, deletion, phase metadata,
    description, homepage URL, and managed binary upload
  - plugin binary validation that rejects random text, directories, missing
    executables, and non-executable paths before registration
- Implemented Tool Runs `/runs` and `/sessions/:id/runs`:
  - per-session tool run table
  - stdout/stderr/raw argument slide-in log drawer with compact log tabs
- Implemented Settings `/settings` for storage, server, tool, plugin, LLM,
  frontend, and CVE visibility without exposing API-key values, including live
  current-theme reporting, a sanitized effective-config copy action, and
  collapsible raw config disclosure.
- Added shell-level skeleton loaders, retryable API error banners, global search
  across selected-session evidence, keyboard shortcuts, toast notifications,
  first-run dashboard guidance, and Command Center manual session comparison.
- Added lazy-loaded route chunks for graph, chart, report, LLM, findings, tools,
  runs, CVEs, settings, and scan-builder surfaces.
- Added route-level error recovery so transient route chunk failures do not
  leave the operator console as a blank white page.
- Added frontend unit tests for route scoping, scan-profile payload helpers, and
  attack graph edge filtering.
- Command Center lists sessions, stats, priority findings, next actions,
  last-completed scan summary, phase-first progress, and recent events.
- Implemented Dashboard `/` and `/sessions/:id`:
  - last-completed scan summary with severity counts, monitor delta summary, and
    quick-scan/review CTAs
  - selected-outcome triage card and active/recent session cards with severity strips
  - selected-session stats
  - global finding stats
  - engagement name and target list visibility
  - cooperative pause/resume, cancel, and delete controls
  - WebSocket/API-derived phase-level progress cards using done, failed,
    running, and queued states
  - collapsible tool pipeline details and collapsible live terminal debug feed
  - concise high-level progress feed and recent lifecycle events
- Implemented Monitor `/monitor`:
  - explicit scheduler notice that recurring runs require `nyx serve` to remain
    active
  - last-successful-run, likely missed-window, baseline, and severity-trend
    summary cards
  - before/after surface-change groups for new findings, resolved findings,
    severity changes, new technologies, disappeared endpoints, and new
    endpoint exposure
  - completed-run baseline reset API and UI action
  - persisted finding severity-change diff type and alert trigger support
- Implemented Session Detail `/sessions/:id` using the dashboard/detail data
  surface:
  - metadata
  - live phase tracker
  - tool status indicators
  - real-time finding counter
  - findings table/list
  - severity distribution chart
  - tool coverage matrix
- Implemented Attack Graph `/sessions/:id/graph`:
  - React Flow + dagre chain rendering backed by attack vector and graph edge APIs
  - chain sidebar, node hover highlighting, minimap, controls, and detail panel
  - finding nodes link to Findings triage with selected chain/finding context
  - graph deep links restore the selected chain and finding node
- Implemented Findings `/sessions/:id/findings`:
  - sortable findings table that visually combines normalized findings and
    source findings with source/finding badges
  - composable severity, origin, OWASP/category, tool, status,
    confirmed/inferred, suppression, and evidence-type filters
  - visible greyed suppressed findings instead of hiding them from triage
  - bulk severity/status/remediation workflow for selected normalized findings
  - bulk suppress, mark-reviewed, and selected-finding Markdown export actions
  - split finding detail workspace with decision summary, cross-confirmation
    evidence summary above tabs, and persisted evidence tabs
  - attack-chain usage links in finding detail panels for bidirectional graph
    and triage navigation
  - mobile finding-detail drawer with backdrop isolation
  - keyboard-openable finding rows, Escape detail closing, arrow-key evidence tab
    navigation, focus-visible detail panes, and copyable active evidence text
  - raw HTTP request/response evidence view
  - prominent severity/status/remediation editor for normalized findings
  - persisted field-level triage audit events for operator severity, status, and
    remediation edits
  - validated triage statuses: `open`, `confirmed`, `false-positive`,
    `suppressed`, and `wont-fix`
  - CVE matches
  - empty-state panel instead of empty tables when no findings are available or
    filters hide all findings
- Implemented CVEs `/sessions/:id/cves`:
  - sortable CVE table with package, source, fixability, and exploitability
    filters
  - persistent source badges that distinguish dynamic, dependency-audit, and
    OSINT CVE origins
  - collapsed-row CVSS, severity, affected package/version, fixed version,
    exploitability, and description columns
  - row-level CVE ID and CVSS vector copy actions for report writing
- Implemented Power Features `/sessions/:id/power`:
  - visual operation groups for payloads, credentials, OSINT, AD/BloodHound,
    PoC/callbacks, Burp integration, and request behavior
  - provider readiness strip for GitHub, Shodan, and SecurityTrails
  - explicit active-action review panels that summarize target, scope, attempt
    count, callback/provider behavior, and potential impact before risky
    operator actions run
  - consistent `[REDACTED]` credential display in tables
  - filterable evasion/block event review by type and time range
- Implemented LLM Chat `/sessions/:id/llm`:
  - split conversation/history layout
  - visible LLM tool-call cards
  - parsed tool-call provenance summaries that show which stored session data
    was fetched before displaying expandable raw payloads
  - context-aware suggested prompt chips for post-scan review, finding-focused
    triage, report synthesis, and refocused long-running analysis
  - new-analysis reset that starts a fresh visible working context while
    preserving persisted audit history
  - context summary indicator with approximate usage, working-message count,
    estimated tokens, report-pin count, and reset state
  - visually distinct operator and assistant message treatments
  - assistant response pinning for report-composer candidate sections
  - actionable empty state for missing analyst history and configuration
- Implemented Reports `/sessions/:id/report`:
  - framed HTML preview with report status toolbar
  - pinned LLM analyst notes panel with copy and unpin actions
  - browser previews for HTML, Markdown, and SARIF text outputs, with PDF kept
    download-only
  - SARIF guidance that identifies it as CI/CD/code-scanning import output, not
    a human-readable report format
  - suppressed/dismissed findings appendix toggle
  - custom executive-summary intro prepended to generated report summaries
  - findings section preview showing included findings in report order
  - executive/technical toggle
  - PDF and Markdown download
  - no-session, loading, error, empty-content, and PDF download-only states

### Spec Alignment Follow-ups

- Keep refining dashboard density and keyboard ergonomics as the data volume
  grows.
- Continue improving plugin editing ergonomics after global validated
  registration.
- Do not add decorative landing pages; the first screen remains the app.
- Continue checking high-density pages at small viewports as new API data is
  added; routes, real API data, graph rendering, drawers, evidence expansion,
  prompt chips, and edit workflows are in place.

### Acceptance Criteria

- Every spec UI page has a route and real API data.
- Dashboard remains usable while new detail pages are added.
- Frontend build is verified in CI.

---

## Phase 17: Docker, Makefile, And Release Packaging

**Status:** Implemented
**Spec sections covered:** 3.6, 20, 21

### Existing Baseline

- Frontend build embeds assets into the Go binary.
- Dockerfile builds the frontend, compiles the Go binary, and produces a
  digest-pinned Debian runtime image with common optional scanner tools
  installed.
- docker-compose starts Nyx and Ollama with persistent volumes.
- Makefile covers build, dev, test, web build, lint, opt-in integration tests,
  tool-version smoke, placeholder migrations/sqlc, cleanup, and release
  snapshots.
- GoReleaser snapshot configuration exists for embedded-frontend binaries.

### Implemented Work

- Added `make ci` to run the core CI sequence locally.
- Added `make compose-config` for Docker Compose validation.
- Added `make docker-smoke` and `scripts/docker-smoke.sh` to build the image,
  start Nyx, verify `/api/health`, verify `/api/tools`, and run `nyx version`
  inside the container.
- Added `scripts/tool-version-smoke.sh` and `make tool-version-smoke` to verify
  Docker-bundled baseline scanners and report optional scanner versions.
- Replaced the placeholder `test-integration` target with an opt-in
  `scripts/integration-smoke.sh` flow guarded by `NYX_RUN_INTEGRATION=1`.
  The suite starts a deterministic vulnerable app, then validates dynamic,
  static audit, combined source-aware correlation, report generation, sidecar
  log retention, and `--lean` sidecar removal against directory-based sessions.
- Added Docker health checks for the image and compose service.
- Added `docs/deployment.md` with Docker, Compose, config mount, and snapshot
  release examples.
- Added `docs/deployment.md` to GoReleaser archives so deployment notes ship
  with release artifacts.

### Spec Alignment Follow-ups

- External scanner availability in Docker should be better than single-binary
  mode, but single-binary mode must remain useful with graceful degradation.
- ProjectDiscovery native adapters remain deferred; subprocess adapters are the
  supported v1 integration path.
- Fixture-backed vulnerable-target scan tests are opt-in and use controlled
  local targets by default.

### Acceptance Criteria

- Docker image can serve the UI and pass API health checks.
- docker-compose starts Nyx and Ollama.
- Makefile targets work locally and in CI.
- Release artifacts include embedded frontend.
- An opt-in fixture-backed smoke test verifies local scan, static audit,
  combined correlation, lean mode, sidecar logs, and reports end to end.

---

## Phase 18: Testing And CI

**Status:** Implemented
**Spec sections covered:** 19

### Existing Baseline

- Go unit/API tests exist.
- Adapter parser tests exist for MVP external adapters.
- Frontend builds locally and in CI with `npm run build`.
- CI runs Go tests, govulncheck, production `gosec`, frontend
  build/typecheck, binary build, Docker image build, Compose validation, Docker
  smoke, and GoReleaser snapshot.

### Implemented Work

- Unit coverage exists for:
  - scope checker
  - DAG topological sort
  - scheduler/rate limits
  - CVE correlator matching
  - attack vector rule evaluation
  - LLM config/context/tool/audit behavior
  - report generation
  - config defaults and env overrides
- Adapter parser tests cover the current external adapter slice without
  requiring scanner binaries, including messy scanner output, negative SQLMap
  output, Dalfox text fallback output, ignored 404 FFUF rows, service-less Nmap
  ports, and normalized raw evidence retention.
- API tests cover core REST endpoints, expanded vector/CVE/report/LLM endpoints,
  auth behavior including cookie login and rate limiting, scan stop, and
  WebSocket lifecycle replay.
- Frontend build verification is part of CI.
- Lint target runs Go lint when `golangci-lint` is installed and always runs
  the frontend build/typecheck.
- Opt-in integration smoke is documented and guarded by `NYX_RUN_INTEGRATION=1`.
  It runs manually/nightly in a dedicated GitHub Actions workflow and uploads
  fixture logs, scan logs, SARIF, and Markdown reports on failure.
- Docker smoke is part of CI.
- Linux full-tool validation scripts remain available for manual acceptance
  runs on hosts where external tools are installed.
- README media capture is available through `make readme-media`. It starts the
  local vulnerable fixture, creates a temporary session, seeds deterministic
  demo LLM history, and captures UI screenshots under `docs/assets/readme/`.

### Spec Alignment Follow-ups

- CI should not require dangerous external scanners or vulnerable targets unless
  explicitly running integration tests.
- Full external scanner validation should remain a manual acceptance path until
  tool installation/runtime variance is low enough for CI.
- Add more fixture coverage for future adapters as they become richer.
- Future feature planning should use `docs/nyx-power-features-spec.md` as the
  enhancement backlog and `docs/power-feature-plans/` for implementation
  handoff.

### Acceptance Criteria

- `go test ./...` passes.
- Frontend build passes in CI.
- Adapter parser tests do not require scanner binaries.
- Integration tests are opt-in and documented.

---

## Architecture Deviations And Rationale

The canonical spec now reflects the current v1 architecture rather than older
greenfield assumptions:

- `net/http` remains the API router. The route surface is explicit and stable,
  and a `chi` migration would be churn unless routing complexity changes.
- The handwritten SQLite store remains the query layer. `sqlc` is deferred until
  query volume or review burden makes generated accessors worth the migration.
- Per-session SQLite directories remain the supported persistence model.
  PostgreSQL is deferred for a future team/multi-user deployment mode.
- ProjectDiscovery tools remain subprocess adapters. Native Go-library adapters
  can be evaluated later, starting with `httpx`; `nuclei` and `naabu` remain
  deferred because they add the most dependency, template, privilege, and
  resource-management risk.

---

## Phase 19: Spec Traceability Matrix

**Status:** Implemented
**Spec sections covered:** 1-23

| Spec section | Implementation phase | Current status | Notes |
| --- | --- | --- | --- |
| 1. Project Overview | Phase 0 | Implemented | Local-first CLI and web UI, scoped sessions, normalized persistence, LLM, reporting, packaging, and CI exist. |
| 2. Design Principles | Phases 0, 3, 4, 5, 11, 12 | Implemented | Scope/evidence/normalization, DAG scheduling, deterministic vectors, constrained LLM analysis, auth, reports, and UI routes exist. |
| 3. Tech Stack | Phases 0, 2, 12, 15, 16, 17 | Implemented | Go, SQLite, React/Vite, WebSocket, OpenAI-compatible LLM client, reports, Docker, Compose, Makefile, and GoReleaser exist. |
| 3.1 Backend Go | Phases 0, 5 | Implemented | Current Go target is 1.26.4 or newer within the 1.26 line; scheduler exists. Native ProjectDiscovery migration is intentionally deferred. |
| 3.2 Dependencies | Phases 0, 10, 12, 15, 17, 18 | Implemented | SQLite, stdlib `net/http`, WebSocket, Viper, go-pdf/fpdf, x/sync, slog, testify, Cytoscape helper types, and Recharts are present; chi/sqlc/PostgreSQL are deferred architecture tracks. |
| 3.3 Frontend | Phase 16 | Implemented | Dashboard, findings, React Flow/dagre Attack Paths, Recharts severity chart, LLM, and reports routes use real API data. |
| 3.4 Database | Phase 2 | Implemented | Per-session SQLite, ordered migrations, and store methods cover Phase 2 persistence; optional Postgres remains later. |
| 3.5 Plugin System | Phase 4 | Implemented | JSON contract, CLI install/list, plugin persistence, configured plugin loading, and failed tool-run degradation exist. |
| 3.6 Packaging | Phase 17 | Implemented | Docker, Compose, Makefile, Docker smoke, deployment notes, CI build, and snapshot release exist. |
| 4. Project Structure | All phases | Implemented | Current structure is documented as the v1 architecture; old chi/sqlc/generated-query layout is no longer treated as mandatory. |
| 5. Core Data Models | Phase 1 | Implemented | Canonical models, report metadata models, additive CVE version fields, and serialization/validation tests exist. |
| 6. Database Schema | Phase 2 | Implemented | Schema covers sessions, targets, findings, evidence, technologies, CVEs, vectors, tool runs, LLM analyses, plugins, and migrations. |
| 7. Tool Adapter System | Phase 4 | Implemented | Built-in registry and configured subprocess plugin adapters coexist; broader ecosystem docs remain later. |
| 8. Tool Pipeline | Phases 6-9 | Implemented | Recon, fingerprinting, enumeration, and vulnerability-scanning adapter slices now cover Phases 6-9; ProjectDiscovery subprocess adapters remain the supported v1 path. |
| 9. DAG Engine | Phase 5 | Implemented | Dependency levels, same-level concurrency, semaphores, timeout/delay controls, prior-result propagation, and phase events exist. |
| 10. LLM Integration | Phase 12 | Implemented | Optional OpenAI-compatible client, config, structured context builder, constrained tools, analyst loop, evidence truncation, persisted audit trails, vector annotations, API endpoints, CLI commands, and UI history/chat exist. |
| 11. CVE Intelligence | Phase 10 | Implemented | Correlator, offline JSON source, Exploit-DB CSV source, cache, NVD/OSV/CIRCL/Vulners/GitHub parsers, evidence CVE extraction, persisted matches, and draft vectors exist. |
| 12. Attack Vector Engine | Phase 11 | Implemented | Deterministic rule engine, default rules, scoring, steps, persistence integration, CVE vector merging, LLM review annotations, API exposure, and React Flow/dagre UI review exist. |
| 13. REST API Surface | Phase 13 | Implemented | Spec endpoints for sessions, scans, findings, finding updates, vectors, CVEs, LLM, reports, health, tools, auth, monitor configs/runs/changes, power-feature records/actions, provider statuses, callbacks, Burp REST helpers, and WebSocket alias exist. |
| 14. CLI Commands | Phase 14 | Implemented | Scan flags, monitor/payload/creds/osint/ad/poc/burp commands including safe validation/provider/credential/Burp actions, report generation, LLM commands, config init/show, plugins, sessions, serve, and version exist. |
| 15. Web UI Pages | Phase 16 | Implemented | Dashboard, monitor route, power features workspace, session route, React Flow/dagre Attack Paths, Recharts severity chart, finding evidence/edit workflow, LLM, and reports pages use real API data. |
| 16. Configuration File | Phase 14 | Implemented | Viper-backed `~/.nyx/config.yaml` defaults, YAML/TOML/JSON parsing, config init/show, env overrides, logging settings, tool path maps, plugin directories, CVE settings, power provider/callback/credential/validation settings with redaction, and CLI override paths exist. |
| 17. Scope Validation | Phase 3 | Implemented | Checker, adapter boundary tests, cancellation, lifecycle status coverage, and privileged API source/LLM allowlist controls exist. |
| 18. Error Handling & Logging | Phases 3, 4, 5 | Implemented | Tool failures persist without failing scans; structured slog configuration supports `NYX_LOG_LEVEL` and `NYX_LOG_FORMAT`, and non-fatal adapter failures are logged. |
| 19. Testing Strategy | Phase 18 | Implemented | Go/API/adapter/config/report/LLM/power tests, govulncheck, production gosec policy, frontend CI build, Docker smoke, scheduled/manual fixture-backed integration smoke, opt-in power integration smoke, opt-in browser smoke with screenshot capture and console-error checks, README fixture media capture, and opt-in Linux full-tool fixture validation scripts exist. |
| 20. Docker Setup | Phase 17 | Implemented | Dockerfile, healthcheck, compose, deployment docs, bundled scanner version smoke, and Docker smoke exist. |
| 21. Makefile | Phase 17 | Implemented | Build, CI, test, security-scan, integration smoke, power integration smoke, browser smoke, README media capture, tool-version smoke, Linux full smoke, lint, web, compose, Docker smoke, migration, cleanup, and release snapshot targets exist. |
| 22. Build Order Recommendation | This plan | Implemented | This roadmap follows the spec build order while preserving current work. |
| 23. Security & Legal Notes | Phase 0 | Implemented | README and CLI help include prominent authorized-use warnings; scope remains a hard implementation boundary. |

## Future Power Feature Plans

The v1 roadmap above is implemented. All eight power-feature modules now have a
deep-but-safe implementation slice: optional provider integrations degrade
gracefully, active validation is explicit and fixture-safe, callbacks are
correlated without exfiltration and require API-key auth for evidence writes,
credentials are paced and redacted by default,
and reports/UI expose power evidence. Remaining work is provider breadth and
Linux-tool hardening based on real operator feedback, not new required roadmap
phases. The complete target states remain in `docs/nyx-power-features-spec.md`
and `docs/power-feature-plans/`.

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
