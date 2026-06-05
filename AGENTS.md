# Codex Guidance for Nyx

Use `docs/nyx-project-spec.md` as the canonical product specification. Keep `README.md`, `AGENTS.md`, and `docs/implementation-plan.md` updated after every major implementation change.

## Current State

This repo has a buildable backend with module path `github.com/pridhvi/nyx`, absolute default session storage under `$HOME/.nyx/sessions`, directory-based sessions at `<session-id>/session.db`, raw tool stdout/stderr sidecar logs under `<session-id>/runs/`, a synchronous CLI safe scan path, `nyx audit`, asynchronous API scan start, continuous attack-surface monitoring, deep-but-safe power-feature modules, Docker packaging, CI, and snapshot release configuration. Active scans run built-in `http-probe` and `security-headers` plus optional subprocess adapters for recon (`subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, `waybackurls`), fingerprinting (`whatweb`, `nuclei-tech`, `testssl.sh`, GraphQL introspection, OpenAPI/Swagger discovery, `wpscan`, `droopescan`), enumeration (`ffuf`, `arjun`, hidden JavaScript endpoint discovery through `linkfinder`, `gitleaks`, JavaScript secret scanning, CORS checks, scoped cloud bucket checks), vulnerability scanning (`nuclei-vuln`, `sqlmap`, `dalfox`, SSRFmap, JWT claim review with optional `jwt_tool` supplement, OAuth, brute-force/default credential validation gated to intentionally vulnerable non-production profiles, reflected XSS validation, browser-backed DOM XSS validation with dialog-marker observation for seeded query/hash routes gated to intentionally vulnerable non-production profiles, stored XSS validation gated to intentionally vulnerable non-production profiles, SQL injection validation, open redirect validation including operator-seeded external redirect URLs, file inclusion validation, command injection validation gated to intentionally vulnerable non-production profiles, upload validation, IDOR adjacent-object/secondary-identity checks, workflow-assist review hints, observability-assist review hints, CSP bypass human-assist review, CAPTCHA-protected sensitive-workflow review and exposed CAPTCHA answer checks, CSRF form analysis, weak session ID sampling, SSTI, hardened XXE, `nikto`), CVE intelligence, deterministic and graph-derived attack vector generation, optional local-first LLM analysis with vector annotations, reporting, and `nmap`; `crt.sh` is registered but opt-in. ProjectDiscovery tools remain subprocess adapters for v1; native Go-library adapters are intentionally deferred until a focused evaluation proves they reduce parser/install risk without adding unacceptable dependency or in-process resource risk. Audit mode statically extracts routes, parameters, SQL sinks, file uploads, auth middleware, secrets, SSRF sinks, and deserialization sinks for Python, JavaScript/TypeScript, Go, PHP, Ruby, and Java without executing repository code, and optional `audit/<tool>` adapters degrade gracefully when their binaries are absent unless explicitly selected. Static adapter parsers normalize Semgrep, Bandit, gosec, govulncheck, npm audit, retire.js, safety, Brakeman, SpotBugs, Psalm, trufflehog, gitleaks, and grype output before falling back to generic JSON walking. `nyx scan --source` runs static-only without a target and sequential combined source-aware mode with a target, using `sessions.workload_mode` while preserving `sessions.mode` for scan aggressiveness; combined sessions emit `source_analysis`, `audit`, `dynamic`, and `correlation` phase events. Dynamic scans now accept generic route seeds, static auth headers/cookies, secondary auth context for authorization checks, and form/JSON login auth profiles from CLI/API scan requests; compatible built-in HTTP checks, safe validators, and `ffuf`/`sqlmap`/`dalfox` consume resolved auth context with scope checks while API JSON, scan profiles, and persisted tool-run arguments redact or omit auth secrets. Auth profiles with validation URLs now re-validate/re-login on a bounded interval or before every phase when requested, and emit `auth_status` lifecycle events for valid, invalid, refreshing, refreshed, failed, and skipped states. Monitoring stores host-privileged global configs, runs, and `surface_changes` in `<state-dir>/nyx-state.db`; manual runs create normal session directories, scheduled runs execute while `nyx serve` is running, and diffs compare targets, technologies, and findings against a baseline. Power-feature persistence now covers generated and validated payloads, lockout-aware credential attempts with redacted storage by default, OSINT findings and provider status records, AD entities/relationships/artifacts, block events, PoC results, callback correlation, Burp collaborator config/callbacks, and Burp REST status/scope/issue sync helpers; active actions are explicit, conservative, scope-checked, and API-key-gated when invoked through the API. API scans support single-target, multi-target, static, and combined requests, cooperative pause/resume, cancellation, request-behavior/evasion options, and WebSocket lifecycle events at `GET /api/scan/{id}/events` while keeping polling endpoints as fallback. The API exposes sessions, findings, source findings, finding updates, targets, tool runs, tool-run sidecar log retrieval, stats, vectors, attack graph edges, CVEs with package metadata, monitor configs/runs/surface changes, power-feature records/actions, LLM history/analysis through `go-openai`, reports including SARIF and source/cross-confirmation/tool-coverage sections, effective config, source-directory browsing constrained to canonical `NYX_SOURCE_ROOTS` or default server roots, structured tool inventory, API-key-protected global validated plugin management, API-backed scan profiles, API-key-protected LLM model probing, scan tool selection, validated per-tool parameters, runner options, and API-key enforcement for non-loopback serving and host-privileged API operations. API keys are accepted through headers or the browser's opaque HttpOnly login cookie, never query strings; browser auth sessions are memory-only, expire after 12 hours, are pruned periodically, and are cleared on server restart; failed authentication uses exponential backoff keyed by client and credential fingerprint, cross-origin unsafe requests and WebSockets are rejected, and optional `NYX_SOURCE_ROOTS`/`NYX_LLM_ALLOWED_HOSTS` allowlists constrain privileged API input. Configuration uses Viper-backed YAML/TOML/JSON plus env overrides, structured `slog` settings through `NYX_LOG_LEVEL`/`NYX_LOG_FORMAT`, and resolves explicit relative session dirs relative to the config file. The React/Vite operator console now uses a dense midnight/violet visual system with self-hosted Outfit and JetBrains Mono fonts, command-center navigation, responsive mobile actions, a compact session command strip, readable live progress rows plus recent events, live terminal feed, workload progress tracks, checkbox-driven monitor config/run/change review, consolidated Power Features workspace with provider status, validation actions, callbacks, credential redaction, AD request records, Burp REST actions, and evasion evidence, multi-target/source scan building with server-side source folder browsing, compact scrollable tool selection, a non-overlapping launch review, source evidence filters/context plus grouped source summaries, findings triage with empty states, desktop split details, mobile finding cards, and evidence tabs, Attack Paths route-level in-progress placeholder, Recharts severity charts with theme-aware surfaces, LLM analyst chat with tool-call cards and suggested prompts, CVEs, report states/previews, global plugins, responsive session-aware tool inventory cards, improved tool-run log drawers, saved scan profiles, system health panels with collapsible raw config, and scan configuration. The frontend builds into `internal/api/web/dist`, uses lazy-loaded route chunks and route-level error recovery, and is embedded into the Go binary. Docker smoke verifies bundled baseline scanner versions. The default API port is `6767`. The backend targets Go 1.26.4 or newer within the 1.26 line; keep it buildable with `go test ./...` after every change.

## Engineering Priorities

- Scope validation is a security boundary. Every adapter that makes network requests must validate target host/IP first.
- Normalize all tool output into `internal/models.Finding`.
- Persist raw evidence. Store full tool stdout/stderr as sidecar logs unless `nyx scan --lean` is used; keep HTTP request/response evidence in SQLite.
- Prefer deterministic rule logic for attack vectors; LLM output should annotate, not decide correctness.
- Keep LLM analyst guidance defensive and non-invasive by default: model output
  must not suggest active credential, secret, or exploitability validation
  unless the operator explicitly requests it and the authorized scope is clear.
- Keep external scanner tools optional and degrade gracefully when missing.
- Default to local-only operation: no telemetry, no required cloud API keys.
- Keep README screenshots generated from safe local fixture data with
  `make readme-media`; do not use live targets, real API keys, local model
  names, or customer data in committed docs media.
- Keep container inputs reproducible; Docker builder/runtime images and Compose
  service images should stay digest-pinned, with the runtime on pinned Debian
  stable/slim rather than a rolling distribution.
- Keep subprocess arguments validated through the shared adapter allow-list,
  reject invalid persisted parameters before invoking external tools, and keep
  auth secrets out of persisted args and live process argv.
- Keep built-in scanner HTTP requests on the scanner-owned scoped client:
  redirects and direct dials must remain inside the selected session scope,
  ambient environment proxies must be disabled by default, and `proxy_url`
  should only be honored when explicitly configured.
- Hash-pin configured plugin binaries with SHA-256 at registration or upload
  time, and re-verify the digest before execution so tampered plugins fail as
  tool runs before a subprocess starts.
- Treat power-feature callback recording as privileged evidence mutation:
  require configured API-key auth and do not expose an unauthenticated local
  callback collector that can pollute PoC evidence.
- Keep asynchronous scan goroutines owned by `ScanManager`: server shutdown
  must stop scheduling, cancel active scan contexts, and wait for final
  cancelled/completed status persistence before exit.
- Keep LLM endpoints constrained by the shared base URL validator and
  `NYX_LLM_ALLOWED_HOSTS` wherever model probing, chat, or automatic analysis
  can initiate outbound requests; private, loopback, link-local, multicast,
  unspecified, and metadata-service endpoints require an explicit allowlist
  entry. LLM clients must also reject disallowed redirect targets and
  connect-time DNS results before requests leave the process.
- Keep Burp REST endpoints constrained to loopback unless `NYX_BURP_ALLOWED_HOSTS`
  or `power.burp.allowed_hosts` explicitly allow a remote/private host, and keep
  Burp XML imports scoped to the selected session. Burp REST clients must also
  reject disallowed redirect targets and connect-time DNS results.
- Keep PoC active validation scoped at the final request boundary: persisted
  finding URLs and redirect targets must still match the selected session scope
  before any marker request is sent.
- Keep monitor webhooks egress-guarded: require HTTPS webhook URLs, reject
  local/private/link-local/metadata destinations unless a future explicit
  allowlist is added, and dispatch through a client that does not inherit
  ambient proxy settings.
- Keep effective config and health responses free of absolute local filesystem
  paths; expose readiness/configured indicators instead.
- Keep callback event bodies and subprocess extra args from exposing bearer
  tokens, cookies, or query-string secrets in API/UI output or process argv.
- Use `NYX_SECURE_COOKIES=true` or `server.secure_cookies: true` when Nyx is
  served behind HTTPS termination so browser session cookies always carry the
  `Secure` flag.

## Suggested Next Tasks

The phase roadmap in `docs/implementation-plan.md` is complete from the repository perspective. Future enhancement modules are tracked in `docs/nyx-power-features-spec.md`, with agent-ready implementation plans in `docs/power-feature-plans/`. Benchmark-driven scanner depth is tracked in `docs/benchmark-driven-scanner-depth.md`; DVWA and OWASP Juice Shop should be used as repeatable ground-truth benchmarks for generic scanner improvements, not as app-specific detection shortcuts. App-specific credentials, seed routes, setup, and expected mappings belong in benchmark profiles only. Next tasks should be hardening and depth rather than new roadmap phases:

1. Continue benchmark depth from the verified 2026-05-28 Linux VM baseline on commit `a41272c`: strict Linux tool smoke passed, `NYX_RUN_LINUX_FULL=1 make linux-full-smoke` passed, DVWA reached 14/14 with 42 findings and no failed benchmark tool runs, Juice Shop reached 15/15 with 28 findings and no failed benchmark tool runs, and LM Studio-backed LLM CLI/UI acceptance passed with real persisted DVWA chat history. The opt-in benchmark harness now fails if DVWA drops below 14/14 covered items, Juice Shop drops below 15/15 covered items, or any benchmark tool run exits nonzero unless an explicit local override is set. Focus new depth work on evidence quality for human-assist partials such as DVWA CSP/CAPTCHA and Juice Shop observability/deserialization rather than app-specific shortcuts; observability/deserialization findings already include response context, redacted excerpts, and relevant form metadata where available.
2. Turn any future Linux full-tool acceptance findings into parser/timeout/install fixes, using `scripts/install-linux-tools.sh --execute` plus strict tool smoke as the readiness loop.
3. Add optional code-splitting for any remaining large frontend graph/chart bundle paths.
4. Add more vulnerable fixture scenarios as new deterministic adapters are introduced.
5. Use `NYX_RUN_BROWSER_SMOKE=1 make browser-smoke` for UI regression checks after operator-console changes.
6. Expand power integration fixtures as new safe validation classes are added.
7. Promote selected safe slices from operator-triggered action mode into scanner adapters only after Linux/tool validation and a separate safety review.

Toolchain security note: build and CI runners should use Go 1.26.4 or newer
within the 1.26 line, and CI runs `govulncheck ./...` to catch reachable
standard-library or module advisories before release artifacts are produced.
Run `make security-scan` for the production `gosec` policy; it excludes the
intentionally vulnerable fixture and `G104` cleanup-error noise, while
intentional production findings should carry narrow `#nosec` comments with
reasons.
