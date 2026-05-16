# nox

A local-first web application penetration testing framework that chains 20+ security tools, normalizes findings into a shared database, and uses a local LLM to map attack vectors.

<!-- TODO: Add demo GIF here -->

## What it does

nox is for pentesters, bug bounty hunters, and security researchers who want one local workspace for web app reconnaissance, fingerprinting, enumeration, vulnerability checks, source-aware audit, evidence review, and reporting. It keeps each engagement scoped, stores the scan state in SQLite, keeps full tool stdout/stderr as sidecar logs beside the session database, and lets optional external tools contribute findings without making those tools mandatory.

At a high level, nox creates a scoped session, runs a dependency-aware tool pipeline, normalizes tool output into common target/finding/evidence models, correlates CVEs, builds deterministic and graph-derived attack vectors, lets a local OpenAI-compatible model annotate the results, and generates Markdown, HTML, SARIF, or PDF reports.

It runs entirely locally by default. There is no telemetry, no required cloud service, and no required hosted LLM. Ollama, LM Studio, llama.cpp, and OpenAI-compatible endpoints can be used when LLM analysis is enabled.

## Quick start

| Docker Compose | Single binary |
| --- | --- |
| `docker compose up --build` | `make build` |
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

## Features

- **Scan pipeline:** DAG-driven execution across reconnaissance, fingerprinting, enumeration, and vulnerability phases with optional subprocess tools.
- **Built-in audit:** `nox audit` performs static extraction and optional SAST/dependency tool execution for Python, JavaScript/TypeScript, Go, PHP, Ruby, and Java repositories without executing repository code.
- **Combined mode:** `nox scan --source <repo>` seeds dynamic adapters with source-discovered routes and parameters, then stores static and dynamic findings in one session.
- **Findings & evidence:** Normalized findings, sidecar stdout/stderr retention, HTTP request/response evidence, technologies, CVE correlation, and tool-run history.
- **Attack vector engine:** Rule-based and graph-derived chains with confidence scoring, ordered steps, labelled edges, prerequisite findings, and OWASP mapping.
- **LLM analysis:** OpenAI-compatible local model support, constrained tool calling, persisted audit trail, post-scan analysis, and interactive chat.
- **Reporting:** Markdown, HTML, SARIF 2.1.0, and PDF output in executive or technical modes.
- **Plugin system:** Subprocess JSON contract so adapters can be written in any language.
- **Web UI:** Scan builder, session dashboard, findings workflow, attack graph, CVE table, tool status, LLM chat, settings, and report preview.

## Supported tools

All external tools are optional. Missing tools are recorded as tool runs and the scan continues with available adapters.

| Phase | Tools |
| --- | --- |
| Recon | `http-probe`, `security-headers`, `subfinder`, `dnsx`, `naabu`, `httpx`, `whois`, `waybackurls`, `nmap`, `crt.sh` |
| Fingerprinting | `whatweb`, `nuclei-tech`, `testssl.sh`, GraphQL introspection, OpenAPI/Swagger discovery, `wpscan`, `droopescan` |
| Enumeration | `ffuf`, `arjun`, `linkfinder`, `gitleaks`, JavaScript secret scanning, CORS checks, scoped cloud bucket checks |
| Vulnerability | `nuclei-vuln`, `sqlmap`, `dalfox`, SSRFmap, `jwt_tool`, OAuth checks, SSTI checks, XXE fuzzing, `nikto` |

Static audit tools are registered as `audit/<id>`. Built-in source analyzers always run; optional tools such as `semgrep`, `bandit`, `gosec`, `govulncheck`, `npm audit`, `retire.js`, `safety`, `brakeman`, `spotbugs`, `psalm`, `trufflehog`, `gitleaks`, and `grype` run when installed.

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

tools:
  nmap: /usr/bin/nmap
  ffuf: /usr/bin/ffuf
  sqlmap: /usr/bin/sqlmap
  dalfox: /usr/local/bin/dalfox
```

Sessions are stored as directories under `database.session_dir`: `<session-id>/session.db` plus optional `<session-id>/runs/*.log` sidecars. Use `./bin/nox scan --lean` to discard raw sidecar logs after normalization, or `./bin/nox sessions export <session-id> --output session.zip` to package the database and logs together.

See [docs/](docs/) for the project spec and implementation roadmap.

> **Authorized use only:** nox is intended exclusively for authorized penetration testing, security research, and CTF challenges. Only use it against systems you own or have explicit, written permission to test. Unauthorized scanning or exploitation may be illegal. The authors accept no responsibility for misuse.

## License

GPL-3.0.
