# Changelog

## v0.1.0 - 2026-06-06

Nyx v0.1.0 is the first public release candidate for the local-first web application penetration testing workspace.

### Highlights

- Local-first operator console with an embedded React UI served from a single Go binary.
- Dynamic, static source-audit, and combined source-aware scan workflows.
- Per-session SQLite databases with raw tool stdout/stderr sidecar logs.
- Normalized findings, HTTP evidence, tool runs, source findings, CVEs, attack paths, and report generation.
- Markdown, HTML, SARIF, and PDF report output.
- Optional OpenAI-compatible local LLM analyst for session summaries, chat, and post-scan analysis.
- Docker and Docker Compose packaging with a bundled baseline scanner set.
- Optional subprocess adapters for common web assessment tools, with graceful degradation when tools are absent.
- Hash-pinned plugin binary registration and pre-execution digest verification.
- Hardened API/session security: API-key browser sessions, auth backoff, CSRF/content-type guardrails, CSP/security headers, scoped filesystem browsing, guarded LLM/Burp/webhook egress, and clean scan shutdown handling.

### Platform Support

- Release archives are published for Linux, macOS, and Windows on amd64 and arm64.
- Linux and Docker are the fully validated paths for full-tool scans, external scanner installation, and benchmark coverage.
- macOS and Windows binaries are intended for core Nyx functionality such as the Web UI, built-in checks, static audit, local session storage, reports, and LLM analysis.
- External scanner coverage on macOS and Windows depends on manually installed tools and has not yet received dedicated full-tool acceptance testing.

### Validation Baseline

- Local Go, frontend, security, Docker, and browser-smoke checks passed before release prep.
- Docker smoke passed with the Debian-based runtime image and bundled baseline scanner versions.
- Linux VM strict full-tool smoke passed.
- DVWA benchmark gate passed at 14/14 covered expected items with no failed benchmark tool runs.
- OWASP Juice Shop benchmark gate passed at 15/15 covered expected items with no failed benchmark tool runs.
- LM Studio-backed LLM scan-time, CLI, and API analyst paths passed against fixture data.

### Known Limits

- Full external-tool scanner depth is best supported on Linux or Docker.
- Windows full-tool validation is not claimed for this release.
- Scheduled monitor runs execute only while `nyx serve` is running, with one catch-up run queued for overdue monitors on startup.
- LLM output is advisory; deterministic findings, scope checks, and operator authorization remain authoritative.
