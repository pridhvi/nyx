# Benchmark-Driven Scanner Depth Plan

This plan uses DVWA and OWASP Juice Shop as repeatable ground-truth benchmark
targets to deepen Nyx's generic scanner capabilities. The benchmark suites may
contain target-specific setup, seed routes, credentials, and expected-result
mappings, but core Nyx adapters and validators must not hardcode DVWA or Juice
Shop behavior.

## Goal

Move Nyx from unauthenticated surface discovery toward authenticated,
evidence-backed, human-assist penetration-test workflows while keeping active
behavior explicit, scoped, conservative, and non-destructive.

Success is measured by benchmark coverage and evidence quality, not by raw
finding count. A single confirmed SQL injection with request/response evidence
is more valuable than several generic informational findings.

## Design Rules

- Implement generic scanner capabilities; keep app-specific knowledge in
  benchmark profile files only.
- Scope validation remains mandatory for every generated request and scanner
  invocation.
- Active validation must be opt-in, paced, non-destructive, and bounded by
  per-target limits.
- Findings should be marked `confirmed` only when Nyx has direct evidence.
  Otherwise use lower-confidence findings or benchmark-only partial coverage
  markers.
- Benchmark profiles may provide login flows, CSRF extraction hints, seed
  routes, expected vulnerability classes, and setup/reset commands.
- Core adapters must never contain checks like "if DVWA route" or "if Juice
  Shop challenge".
- Reports must distinguish detected, confirmed, partial, missed, and skipped
  benchmark expectations.

## Benchmark Targets

### DVWA

Use DVWA to exercise small, explicit vulnerability modules with known routes and
low setup complexity:

- brute force
- command injection
- CSRF
- file inclusion
- file upload
- insecure CAPTCHA
- weak session IDs
- JavaScript weakness
- SQL injection
- blind SQL injection
- reflected XSS
- stored XSS
- DOM XSS
- CSP bypass

DVWA is the best first benchmark because authenticated navigation and seeded
module routes should produce measurable coverage quickly.

### OWASP Juice Shop

Use Juice Shop to exercise larger API-heavy and business-logic-heavy workflows:

- broken access control
- broken authentication
- injection
- XSS
- XXE
- insecure deserialization
- sensitive data exposure
- vulnerable components
- unvalidated redirects
- improper input validation
- security misconfiguration
- anti-automation weakness

Juice Shop should be measured by category and challenge signal rather than only
raw challenge count. Many challenges require multi-step or puzzle-like reasoning
that should become human-assist output before it becomes automated confirmation.

## Phase 1: Benchmark Harness

Add repeatable commands and artifact collection:

- `make benchmark-targets-up`
- `make benchmark-targets-down`
- `make benchmark-dvwa`
- `make benchmark-juice`
- `make benchmark-all`

Artifacts should be written under `artifacts/benchmarks/<timestamp>/` and
include:

- target container logs
- Nyx session directories
- generated Markdown reports
- generated SARIF reports
- benchmark summary JSON
- raw tool sidecar logs when not using lean mode
- scan command lines and environment metadata

The harness should reset target state between runs where the app supports it.
If reset is not available, the summary must record that the target was reused.

Acceptance criteria:

- One command starts both targets and verifies health.
- One command runs each benchmark and writes a summary JSON.
- Benchmark setup validates DVWA authentication plus low security level and
  creates or reuses the Juice Shop benchmark user before scans start.
- Benchmark commands are opt-in and do not run in normal push CI.
- Failure artifacts are preserved.

## Phase 2: Ground-Truth Mapping

Create benchmark profile files, for example:

- `benchmarks/dvwa/profile.json`
- `benchmarks/dvwa/expected.json`
- `benchmarks/dvwa/routes.txt`
- `benchmarks/juice-shop/profile.json`
- `benchmarks/juice-shop/expected.json`
- `benchmarks/juice-shop/routes.txt`

Expected mappings should use generic classes:

- `sql_injection`
- `blind_sql_injection`
- `reflected_xss`
- `stored_xss`
- `dom_xss`
- `command_injection`
- `file_upload`
- `file_inclusion`
- `csrf`
- `weak_session_id`
- `open_redirect`
- `idor`
- `broken_authentication`
- `sensitive_data_exposure`

Mappings can use `match` for legacy "any matching field is enough" behavior, or
`all_match` when a benchmark item should only count if every specified field
matches the same finding. Use `all_match` for high-signal validations such as
tool plus seeded route plus title/status so broad misconfiguration findings do
not inflate benchmark coverage.
- `security_misconfiguration`
- `vulnerable_component`
- `xxe`
- `insecure_deserialization`

Each expected item should include:

- stable ID
- vulnerability class
- route or route pattern
- parameter hints when known
- authentication requirement
- expected severity range
- confirmation strategy
- whether the expectation is automation-suitable or human-assist-only

Acceptance criteria:

- DVWA expected mapping covers all current module directories.
- Juice Shop expected mapping covers categories first, then selected challenge
  signals where a generic validator can reasonably detect them.
- Coverage summary can show detected, confirmed, partial, missed, and skipped.

## Phase 3: Authenticated Scan Profiles

Add reusable authenticated scanning support that real operators can use outside
the benchmarks:

- static cookie/header auth profile (implemented for CLI/API/UI scan requests)
- bearer token auth profile (implemented through JSON-login token extraction and static headers)
- login-form flow (implemented for generic form profiles)
- CSRF token extraction from HTML forms (implemented for login and post-login form steps)
- token extraction from response body/header
- cookie jar persistence per scan session
- auth validation request (implemented with status and body marker checks)
- session refresh or re-login when validation fails

Benchmark-specific examples:

- DVWA: login as `admin:password`, capture `PHPSESSID`, set security level, and
  carry the CSRF token where needed.
- Juice Shop: create or login a benchmark user, capture JWT or browser storage
  token, and scan authenticated API/UI routes.

Acceptance criteria:

- Auth profile format is target-agnostic.
- Dynamic adapters receive an authenticated HTTP client or request context.
- Auth failures are visible as tool runs or scan events.
- Auth validation and refresh events are visible over the scan lifecycle stream.
- Secrets are redacted from logs, effective config, reports, and API responses.

Current state: Nyx accepts route seeds, static auth headers/cookies, and generic
auth profile JSON through the CLI and API/UI scan builder. Built-in HTTP checks
apply those values to requests, and `ffuf`, `sqlmap`, and `dalfox` receive
compatible subprocess flags with persisted arguments redacted. Form login
profiles support CSRF extraction, post-login form steps, cookie capture, and
validation requests. JSON login profiles support token extraction into a
configured auth header. Profiles with a `validation_url` are re-validated during
long scans and re-run when validation fails; `refresh_interval_seconds` controls
the default interval and `validate_each_phase` forces validation before every
adapter phase for short-lived benchmark sessions. Auth validation, invalidation,
refresh, failure, and skip states emit `auth_status` events.

DVWA benchmark setup initializes the database with the setup CSRF token when an
authenticated login reaches the setup page, then validates login plus low
security before the scan starts.

## Phase 4: Route And State Seeding

Improve crawler and adapter reach without target-specific scanner code:

- seed URLs from files (implemented for CLI) and scan requests (implemented for API/UI)
- OpenAPI/Swagger route ingestion
- frontend route extraction from JavaScript bundles
- HTML form extraction
- query/body/header parameter candidate extraction
- source-aware route and sink hints from `nyx scan --source`
- route deduplication and scope filtering

Seeded routes should flow into:

- `ffuf`
- `arjun`
- `dalfox`
- `sqlmap`
- SSRF/open redirect checks
- XXE checks
- upload validation
- IDOR/differential-access probes

Acceptance criteria:

- Seed routes are recorded in the session as operator-provided or discovered
  inputs.
- Adapters can consume route/parameter hints without requiring benchmark logic.
- Reports show route discovery sources and tested route counts.

## Phase 5: Safe Validation Engines

Add generic, bounded validators for common classes:

- reflected XSS marker validation (implemented for seeded query routes)
- stored XSS marker recall where a read-back route is known or discovered
  (implemented for explicitly safe benchmark profiles)
- DOM XSS candidate detection with browser-assisted confirmation (implemented
  for explicitly safe benchmark profiles with installed Chrome/Chromium)
- SQL injection boolean/error validation with strict limits (implemented for
  seeded query routes; time-based probing remains deferred)
- open redirect validation with controlled marker URLs (implemented for seeded
  redirect-like query parameters without following external redirects)
- command injection marker checks only when the configured profile marks the
  target as intentionally vulnerable and non-production (implemented for seeded
  command-like forms)
- harmless file upload and retrieval validation (implemented for seeded upload
  routes; accepted-but-not-retrieved uploads remain suspected)
- IDOR adjacent-object checks and secondary-identity replay (implemented for
  seeded object identifier routes; adjacent-object access remains suspected
  unless a secondary identity can replay the same object successfully)
- file inclusion path marker checks with safe local-only payloads (implemented
  for seeded file/path query parameters)
- CORS validation
- XXE non-exfiltrating marker validation (implemented with internal XML entity
  markers; no file or network entity exfiltration)
- weak session ID sampling (implemented for seeded session-related routes)
- CSRF missing-token checks (implemented as non-mutating form analysis for
  seeded state-changing routes; token-reuse checks remain deferred)

Acceptance criteria:

- Validators only run in active mode and honor scope/auth context.
- External redirect markers are never followed by the built-in validator.
- Confirmed findings are emitted only when a raw XSS canary tag is reflected, a
  unique marker is returned in a redirect `Location`, SQL true/false predicates
  produce a repeatable differential response, an upload marker is echoed or
  retrieved, or an XML internal entity marker is resolved.
- SQL error indicators are recorded as suspected findings, not confirmed
  exploitation.
- Tool-run sidecar logs record tested candidates without persisting secrets.
- Validators produce normalized findings with request/response evidence.
- Validators record inconclusive and skipped states instead of over-claiming.
- Active validators are disabled by default unless explicitly selected by CLI,
  API, or benchmark profile.
- Rate limits and request budgets are enforced per target and per validator.

## Phase 6: Differential Authorization And IDOR

Add a generic two-identity test framework:

- create or configure user A and user B auth profiles
- discover object-like IDs in URLs, JSON bodies, and API responses
- replay same-object requests under another identity
- detect status/body/semantic differences
- avoid destructive methods unless explicitly allowed and benchmark-safe
- persist candidate and confirmed authorization findings separately

Benchmark use:

- Juice Shop basket/profile/order flows.
- DVWA forced browsing or protected-module checks where applicable.

Acceptance criteria:

- Two-identity tests are reusable for real apps.
- Findings include both identities' redacted request/response evidence.
- The engine avoids state-changing probes unless the profile allows them.

## Phase 7: Business Logic Assist

Implement conservative human-assist workflows before full automation:

- price/quantity tampering candidates
- role mismatch candidates
- forced browsing candidates
- anti-automation/rate-limit observations
- account recovery/password reset flow observations
- workflow state-machine anomalies
- attack-path suggestions tied to persisted evidence

Acceptance criteria:

- Business logic output defaults to candidate or human-review status
  (implemented for seeded high-value forms and business-control parameters).
- Confirmed findings require direct differential evidence.
- Reports clearly separate automated confirmation from suggested manual review.

## Phase 8: Benchmark Reports

Add benchmark-specific output alongside normal Nyx reports:

```text
DVWA Benchmark
Covered: 12/14
Confirmed: 9/14
Detected: 2/14
Partial: 1/14
Missed: 2/14
Skipped: 0/14

Brute Force: confirmed
SQL Injection: confirmed
Reflected XSS: confirmed
Stored XSS: confirmed
DOM XSS: confirmed
File Inclusion: confirmed
Command Injection: confirmed
Weak Session IDs: confirmed
File Upload: detected
CSRF: detected
```

The JSON summary should include:

- target name and version
- Nyx commit/version
- scan profile
- expected item count
- detected count
- confirmed count
- partial count
- missed count
- skipped count
- finding IDs mapped to expected items
- missed expectation reasons when known
- tool failures that may affect coverage

Acceptance criteria:

- Benchmark report does not replace normal reports.
- Coverage deltas can be compared across runs.
- SARIF and Markdown reports continue to include normal findings.

## Phase 9: CI Integration

Add scheduled/manual benchmark CI only after the harness is stable:

- `NYX_RUN_BENCHMARKS=1 make benchmark-all`
- nightly/manual GitHub Actions workflow
- upload benchmark artifacts on failure
- compare coverage against a checked-in baseline
- initially warn on absolute misses
- fail only on regressions from the baseline

Acceptance criteria:

- Normal push CI remains fast.
- Benchmark CI is reproducible on Linux.
- Coverage baseline updates are intentional and reviewed.

## Initial Targets

Latest Linux VM acceptance baseline from this track:

- DVWA: 12 of 14 modules covered, with brute-force/default credential,
  regular SQL injection, blind SQL injection, reflected XSS, stored XSS, file
  inclusion, DOM XSS, command injection, and weak session ID confirmed by
  built-in validators; current full-tool benchmark runs have no failed tool
  runs. The remaining missed DVWA modules are insecure CAPTCHA and CSP bypass.
- Juice Shop: 4 of 15 categories covered; this is the current shared-validator
  regression floor, and current full-tool benchmark runs have no failed tool
  runs.

Short-term:

- DVWA: maintain at least 12 of 14 modules covered while improving CSP or
  workflow/CAPTCHA review signals.
- DVWA: maintain confirmed brute-force/default credential, SQL injection,
  reflected XSS, stored XSS, DOM XSS, file inclusion, command injection, and
  weak session ID coverage in benchmark-safe mode.
- Juice Shop: identify at least 25 category-level challenge signals or route
  risks.
- Juice Shop: confirm at least OpenAPI exposure, CORS/header issues, selected
  XSS/redirect/API-access issues where safe.

Strong target:

- DVWA: 12 or more modules detected, with several confirmed.
- Juice Shop: 50 or more challenge signals or category-level detections.
- Authenticated crawling, route seeding, and validator evidence become reusable
  for real authorized targets.

## Implementation Priority

1. Benchmark harness and artifact layout.
2. DVWA ground-truth profile and route seeds.
3. Generic auth profile support.
4. DVWA authenticated seeded scan.
5. Generic route/parameter seeding into dynamic adapters.
6. Safe reflected XSS, SQL injection, and open redirect validators.
7. Juice Shop profile and authenticated API route seeding.
8. CORS and weak-session validators.
9. Differential authorization and IDOR framework.
10. Benchmark coverage reports.
11. Manual/nightly benchmark CI.
12. Business logic assist workflows.

## Non-Goals For This Track

- Do not hardcode DVWA or Juice Shop routes in scanner adapters.
- Do not run destructive exploit payloads.
- Do not claim full human-equivalent coverage.
- Do not broaden ProjectDiscovery native-library migration; subprocess adapters
  remain the v1 path.
- Do not promote active validators into default scans without a separate safety
  review.
