# Module 3 Implementation Plan: Credential Testing

Current repository state: an initial production-safe slice is implemented with
session DB credential records, API/CLI/UI visibility, redaction by default, and
API-key-gated test recording. Active login attempts currently require explicit
operator-supplied usernames and passwords; no built-in default credential list is
used. Remaining depth should add fixture-safe login adapters, lockout-aware
spraying, curated defaults behind a separate safety review, and report summaries.

## Goal And Success Criteria

Add explicit credential testing for discovered web services and login endpoints:
default credential checks, cautious password spraying, and correlation of
credentials found by other Nyx modules. The feature must be useful for
authorized tests while making lockout and abuse risks visible.

Done means:

- A new `credential_test` phase exists but does not run unless selected.
- Credential findings are persisted, redacted according to config, and linked to
  normal findings when valid credentials are confirmed.
- Default credential and spray actions are rate-limited and lockout-aware.
- Operators can list and inspect credential results through API, CLI, and UI.

Out of scope:

- Large breach corpus ingestion.
- Unbounded brute forcing.
- Cloud identity provider attack automation.

## Safety Constraints

- Credential testing is opt-in and requires explicit tool/phase selection.
- API-triggered credential actions require configured API-key auth.
- Defaults must be conservative: low concurrency, delay between attempts, and
  small curated wordlists.
- Stop immediately for a target when lockout indicators appear.
- Passwords are redacted by default in API/UI unless config allows plaintext for
  a local engagement.
- Never test credentials against out-of-scope hosts.

## Data Model And Migration

Add phase constant `credential_test` in `internal/adapters`.

Add migration `006_credential_testing.sql` if implemented alone, or the next
available migration if other modules land first:

- `credential_findings`
  - id, session_id, target_id, finding_id,
  - credential_type,
  - username, password,
  - service, url,
  - valid, lockout_detected,
  - evidence,
  - created_at.
- Indexes on session, target, valid, credential_type.

Add `models.CredentialFinding`.

Store methods:

- `InsertCredentialFinding`
- `ListCredentialFindings(sessionID, filter)`
- `UpdateCredentialFinding`
- `CredentialFindingByID`

Add config:

- `credentials.enabled_default=false`
- `credentials.store_plaintext=false`
- `credentials.max_attempts_per_account`
- `credentials.max_attempts_per_target`
- `credentials.delay_ms`
- `credentials.hibp_api_key`

## Backend Architecture

Create `internal/creds`:

- `engine.go`: orchestrates credential phase.
- `defaults.go`: default credential database and matching by technology.
- `sprayer.go`: lockout-aware spray engine.
- `discover.go`: login endpoint discovery from findings/source/routes.
- `correlator.go`: tests discovered credentials across compatible services.
- `hibp.go`: optional HIBP client.
- `redact.go`: plaintext/redaction policy.
- `wordlists/`: curated defaults and small spray list.

Integration options:

- Implement credential testing as an adapter with phase `credential_test`, or as
  an engine post-phase runner. Prefer adapter shape so phase/tool selection
  stays consistent.
- Add default safe credential adapter only when selected by phase/tool. It must
  not run as part of `DefaultSafeAdapters()` unless selected filtering includes
  the phase.

Credential discovery sources:

- Login endpoints from source findings, ffuf/arjun findings, OpenAPI routes,
  GraphQL endpoints, and common technology login paths.
- Usernames from OSINT findings when Module 4 exists; otherwise from explicit
  user input or source findings.
- Passwords from curated wordlist and credentials found in source/response
  findings.

Lockout detection:

- Track HTTP 423, 429, common lockout strings, repeated redirect to reset flows,
  and account-disabled messages.
- Stop testing that username/service when detected and persist
  `lockout_detected=true`.

## API And CLI

API:

- `GET /api/sessions/{id}/credentials?valid=&type=&service=`
- `GET /api/sessions/{id}/credentials/{credential_id}`
- `POST /api/sessions/{id}/credentials/test`
  - Body selects mode: defaults, spray, correlate.
  - Requires configured API key.
- `POST /api/sessions/{id}/credentials/{credential_id}/redact`

CLI:

- `nyx creds test <session-id> --mode defaults|spray|correlate`
- `nyx creds list <session-id> [--valid-only] [--format json]`
- `nyx creds redact <session-id> --id <credential-id>`

CLI should print redacted passwords unless `store_plaintext=true`.

## Frontend

Add a session-scoped Credentials page or panel:

- Summary cards: valid, invalid, lockout, services tested.
- Table grouped by service/URL with type, username, password redaction, valid
  state, lockout state, and evidence.
- Action panel for explicit test run:
  - mode,
  - max attempts,
  - delay,
  - username/password inputs or uploaded small list.
- Strong warning before spray mode.

## Implementation Order

1. Add phase constant, model, migration, store methods, tests.
2. Add config fields and redaction policy tests.
3. Add login endpoint discovery with fixtures.
4. Add default credential tester for HTTP form/basic auth style fixtures.
5. Add sprayer with lockout detection and tests.
6. Add credential adapter/engine integration.
7. Add API and CLI.
8. Add UI.
9. Add report summary section for valid credentials and lockout warnings.

## Tests And Acceptance

Run:

```sh
go test ./...
cd web && npm run build
```

Targeted tests:

- Credential phase does not run by default.
- Out-of-scope credential target is rejected.
- Passwords are redacted by default.
- Lockout detection stops attempts.
- Default credential fixture produces a valid credential finding.
- API auth blocks explicit test action without API key.
- UI shows redacted values and warning copy.

Acceptance scenario:

1. Add local fixture login route with safe demo credentials.
2. Run credential test explicitly.
3. Confirm one valid credential finding, sidecar tool run, API/CLI/UI visibility,
   and no plaintext leak when redaction is enabled.
