# nox

A local-first web application penetration testing framework that chains 20+ security tools, normalizes findings into a shared database, and uses a local LLM to map attack vectors.

## What it does

nox is for pentesters, bug bounty hunters, and security researchers who want one local workspace for web app reconnaissance, fingerprinting, enumeration, vulnerability checks, source-aware audit, evidence review, and reporting. It keeps each engagement scoped, stores the scan state in SQLite, keeps full tool stdout/stderr as sidecar logs beside the session database, and lets optional external tools contribute findings without making those tools mandatory.

At a high level, nox creates a scoped session, runs a dependency-aware tool pipeline, normalizes tool output into common target/finding/evidence models, correlates CVEs, builds deterministic and graph-derived attack vectors, lets a local OpenAI-compatible model annotate the results, and generates Markdown, HTML, SARIF, or PDF reports.

It runs entirely locally by default. There is no telemetry, no required cloud service, and no required hosted LLM. Ollama, LM Studio, llama.cpp, and OpenAI-compatible endpoints can be used when LLM analysis is enabled.

When serving beyond loopback, Nox requires `NOX_API_KEY` or `server.api_key`. Host-privileged API operations, including plugin management, API source scans, and LLM endpoint probing, require API-key authentication even in local mode. The browser console uses an HttpOnly session cookie after API-key login; API keys are accepted in `X-Nox-API-Key` or `Authorization: Bearer` headers, not in query strings.

## Quick start

| Docker Compose | Single binary |
| --- | --- |
| `NOX_API_KEY=$(openssl rand -hex 24) docker compose up --build` | `make build` |
| `curl http://127.0.0.1:6767/api/health` | `./bin/nox scan --target https://example.com --no-llm` |

After building the binary, you can also run:

```sh
./bin/nox serve --host 127.0.0.1 --port 6767
```

Static and combined source-aware modes use the same session database and report pipeline:

```sh
./bin/nox audit /path/to/repo --no-llm --format sarif --output audit.sarif
./bin/nox scan --target https://example.com --source /path/to/repo --no-llm
```

For authenticated or deeper dynamic scans, route seeds and auth material can be
provided without hardcoding target behavior into adapters:

```sh
./bin/nox scan --target https://example.com \
  --route-seed-file routes.txt \
  --auth-profile auth-profile.json \
  --auth-header "Authorization: Bearer <token>" \
  --secondary-auth-header "Authorization: Bearer <second-user-token>" \
  --auth-cookie "session=<cookie>" \
  --no-llm
```

Seed routes are scope-checked before use. Auth headers/cookies are applied to
compatible built-in HTTP checks and subprocess adapters such as `ffuf`,
`sqlmap`, and `dalfox`; API session JSON and persisted tool-run arguments
redact those secret values. Secondary auth headers/cookies are only used by
authorization checks such as `idor-check` to compare access as another identity.
Saved scan profiles keep route seeds and scanner options but intentionally omit
auth secrets.

`--auth-profile` accepts target-agnostic JSON for form or JSON login flows. Form
profiles can extract an HTML CSRF token, submit username/password fields, run
bounded post-login form steps, and validate the session with a follow-up URL:

```json
{
  "type": "form",
  "login_url": "/login",
  "username": "user",
  "password": "pass",
  "username_field": "username",
  "password_field": "password",
  "csrf_field": "csrf",
  "validation_url": "/account",
  "validation_contains": "Account",
  "refresh_interval_seconds": 300,
  "validate_each_phase": false
}
```

When `validation_url` is present, Nox re-validates the resolved auth context
during longer scans and re-runs the profile if validation fails. Set
`refresh_interval_seconds` to tune the validation/re-login interval, or
`validate_each_phase` for fragile benchmark sessions that should be checked
before every adapter phase. Auth validation, invalidation, and refresh outcomes
are emitted as scan lifecycle events.

JSON login profiles can extract a token into an auth header:

```json
{
  "type": "json_login",
  "login_url": "/api/login",
  "username": "user@example.test",
  "password": "pass",
  "token_json_path": "authentication.token",
  "auth_header": "Authorization",
  "auth_header_prefix": "Bearer "
}
```

## Features

- **Scan pipeline:** DAG-driven execution across reconnaissance, fingerprinting, enumeration, and vulnerability phases with optional subprocess tools.
- **Built-in audit:** `nox audit` performs static extraction and optional SAST/dependency tool execution for Python, JavaScript/TypeScript, Go, PHP, Ruby, and Java repositories without executing repository code.
- **Combined mode:** `nox scan --source <repo>` runs audit first, then source-aware dynamic adapters, then a shared correlation phase in one session.
- **Findings & evidence:** Normalized findings, sidecar stdout/stderr retention, HTTP request/response evidence, technologies, CVE correlation, and tool-run history.
- **Attack vector engine:** Rule-based and graph-derived chains with confidence scoring, ordered steps, labelled edges, prerequisite findings, and OWASP mapping.
- **LLM analysis:** OpenAI-compatible local model support, constrained tool calling, persisted audit trail, post-scan analysis, and interactive chat.
- **Reporting:** Markdown, HTML, SARIF 2.1.0, and PDF output with source findings, tool coverage, dependency CVEs, suppressed findings, and cross-confirmed evidence.
- **Continuous monitoring:** `nox monitor` stores recurring scan configs in the global state DB, creates normal session runs, diffs each run against a baseline, and records attack-surface changes.
- **Power-feature modules:** Operator-triggered workspace for LLM-assisted payloads with safe fixture validation, lockout-aware credential checks, provider-backed OSINT status, AD/BloodHound records, evasion/block events, callback-backed PoC evidence, and Burp XML/REST bridge actions.
- **Plugin system:** Subprocess JSON contract so adapters can be written in any language.
- **Web UI:** Dense midnight/violet operator console with bundled local fonts, command-center dashboard, responsive mobile actions, scan builder rail, monitor workspace, triage split panes with mobile finding cards, grouped source evidence, deduplicated attack paths, CVE table, responsive tool inventory, polished stdout/stderr log drawers, LLM analyst workspace, system health, and report composer.

## Supported tools

All external tools are optional. Missing tools are recorded as tool runs and the scan continues with available adapters.

| Phase | Tools |
| --- | --- |
| Recon | `http-probe`, `security-headers`, `subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, `waybackurls`, `nmap`, `crt.sh` |
| Fingerprinting | `whatweb`, `nuclei-tech`, `testssl.sh`, GraphQL introspection, OpenAPI/Swagger discovery, `wpscan`, `droopescan` |
| Enumeration | `ffuf`, `arjun`, `linkfinder`, `gitleaks`, JavaScript secret scanning, CORS checks, scoped cloud bucket checks |
| Vulnerability | `nuclei-vuln`, `sqlmap`, `dalfox`, SSRFmap, `jwt_tool`, OAuth checks, reflected XSS validation, SQL injection validation, open redirect validation, upload validation, IDOR route checks, workflow-assist review hints, CSRF form analysis, weak session ID sampling, SSTI checks, XXE fuzzing, `nikto` |

Static audit tools are registered as `audit/<id>`. Built-in source analyzers always run; optional tools such as `semgrep`, `bandit`, `gosec`, `govulncheck`, `npm audit`, `retire.js`, `safety`, `brakeman`, `spotbugs`, `psalm`, `trufflehog`, `gitleaks`, and `grype` run when installed. Their native outputs are parsed into normalized findings or package CVEs where possible, with a generic JSON fallback for future adapter shapes.

The Docker image bundles a baseline scanner set (`curl`, `dig`, `ffuf`, `nikto`, `nmap`, `python3`, `sqlmap`, `whatweb`, and `whois`) and verifies those tools during Docker smoke tests. Other external scanners remain optional user-installed tools in single-binary mode and are reported by the tool-version smoke script when present. `scripts/install-linux-tools.sh` prints a dry-run Linux setup plan by default and can install the supported tool set with `--execute`; it prepends user-local Go, Python, Composer, and Ruby paths so broken system shims do not mask working user installs. ProjectDiscovery tools currently run as subprocess adapters; native Go-library integrations are intentionally deferred until they prove worth the added dependency and in-process resource risk.

## Configuration

Create `~/.nox/config.yaml` with the local defaults you care about:

```yaml
database:
  session_dir: ~/.nox/sessions

llm:
  enabled: true
  provider: openai-compatible
  base_url: http://127.0.0.1:11434/v1
  api_key: ollama
  model: llama3:8b

logging:
  level: info
  format: text

power:
  active_validation:
    enabled: false
  callbacks:
    provider: builtin
    interactsh_url: ""
  credentials:
    max_attempts_per_user: 3
    delay_seconds: 3
    store_plaintext: false
  providers:
    github_token: ""
    shodan_api_key: ""
    securitytrails_api_key: ""
  burp:
    base_url: ""
    api_key: ""

tools:
  nmap: /usr/bin/nmap
  ffuf: /usr/bin/ffuf
  sqlmap: /usr/bin/sqlmap
  dalfox: /usr/local/bin/dalfox
```

Sessions are stored as directories under `database.session_dir`: `<session-id>/session.db` plus optional `<session-id>/runs/*.log` sidecars. Use `./bin/nox scan --lean` to discard raw sidecar logs after normalization, or `./bin/nox sessions export <session-id> --output session.zip` to package the database and logs together.

Monitoring state is global rather than per-session. Monitor configs, runs, and `surface_changes` live in `<state-dir>/nox-state.db`, where `<state-dir>` is the parent of `database.session_dir` when that directory is named `sessions`. Scheduled monitor runs execute only while `nox serve` is running; manual runs are available from both CLI and UI:

```sh
./bin/nox monitor create --target https://example.com --schedule '@daily' --name example
./bin/nox monitor run <config-id>
./bin/nox monitor changes <config-id>
```

Advanced modules are explicit and safe by default:

```sh
./bin/nox payloads generate <session-id> --finding <finding-id>
./bin/nox payloads validate <session-id> --payload <payload-id> --confirm --enabled=true
./bin/nox creds test <session-id> --mode defaults --url http://127.0.0.1:18081/login --confirm --max-attempts 2
./bin/nox osint run <session-id> --providers github,shodan,securitytrails
./bin/nox ad kerberoast <session-id> --username svc-http --confirm
./bin/nox poc run <session-id> --finding <finding-id> --confirm --active=true
./bin/nox burp export scope <session-id> --output scope.xml
./bin/nox burp status <session-id>
```

Power-provider secrets are always redacted in effective config, logs, API output,
and UI surfaces. Active validation, credential checks, Burp REST actions, and AD
request records are opt-in; API-triggered active actions require configured
API-key authentication.

For stricter local deployments, set `NOX_SOURCE_ROOTS` to a comma-separated list of allowed repository roots for API-triggered source scans, and `NOX_LLM_ALLOWED_HOSTS` to allowed LLM probe hosts such as `127.0.0.1,localhost,ollama`.

Structured logs use Go `slog`. Set `NOX_LOG_LEVEL=debug|info|warn|error` and `NOX_LOG_FORMAT=text|json` for CLI/server internals without changing human-readable command output.

Run the deeper local fixture integration suite with:

```sh
NOX_RUN_INTEGRATION=1 make test-integration
NOX_RUN_POWER_INTEGRATION=1 make power-integration
NOX_RUN_BROWSER_SMOKE=1 make browser-smoke
```

The integration smoke starts the built-in vulnerable fixture and verifies
dynamic scans, static audits, combined source-aware correlation, reports, and
lean sidecar-log behavior. The power integration smoke additionally verifies
payload validation, credential redaction, provider skip status, PoC records, and
power report sections against deterministic fixture routes. The browser smoke
starts a fixture-backed session, serves the embedded UI, checks dashboard,
findings, power, reports, and attack-path pages in Chromium, fails on console
errors, and writes screenshots to `/tmp/nox-browser-*.png`. The standard
integration suite runs in GitHub Actions on a nightly schedule and on manual
dispatch; the power and browser suites are local opt-in for now.

Benchmark-driven scanner depth uses DVWA and OWASP Juice Shop as repeatable
ground-truth targets for generic scanner improvements. App-specific credentials,
target setup, route seeds, and expected coverage mappings live under
`benchmarks/`; scanner adapters must remain target-agnostic. The benchmark
harness preflights DVWA login plus low security level and creates/reuses the
Juice Shop benchmark user before scanning, so authentication failures are
reported as setup failures instead of noisy low-coverage scans. Active-mode
scans now include bounded, auth-aware built-in validators for reflected XSS
markers, SQL injection boolean/error canaries, harmless file uploads, IDOR
adjacent-object checks with optional secondary-identity replay, workflow-assist
review hints for seeded high-value forms and business-control parameters, CSRF
form-token analysis, weak session identifier sampling, non-exfiltrating XML
entity markers, and open redirects on seeded query routes; they do not follow
external redirects and only report confirmed validation when the marker,
predicate behavior, or secondary-identity replay is observed.

```sh
make benchmark-targets-up
NOX_RUN_BENCHMARKS=1 make benchmark-dvwa
NOX_RUN_BENCHMARKS=1 make benchmark-juice
NOX_RUN_BENCHMARKS=1 make benchmark-all
make benchmark-targets-down
```

Benchmark artifacts are written under `artifacts/benchmarks/<timestamp>/` and
include session directories, normal reports, SARIF, target metadata, and
coverage summaries. See
[docs/benchmark-driven-scanner-depth.md](docs/benchmark-driven-scanner-depth.md)
for the staged plan.

Docker smoke validation builds the image, starts the API, checks health/tools endpoints, runs `nox version`, and verifies bundled scanner versions:

```sh
make docker-smoke
```

See [docs/](docs/) for the project spec, implementation roadmap, future
power-feature modules, and detailed power-feature implementation plans.

> **Authorized use only:** nox is intended exclusively for authorized penetration testing, security research, and CTF challenges. Only use it against systems you own or have explicit, written permission to test. Unauthorized scanning or exploitation may be illegal. The authors accept no responsibility for misuse.

## License

GPL-3.0.
