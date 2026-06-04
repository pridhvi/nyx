# Nyx — Web Application Penetration Testing Framework
## Complete Project Specification & Build Document

> **Purpose of this document:** This is a full technical specification for an AI coding assistant to use as the primary reference when building the Nyx project. It covers architecture, tech stack rationale, all component designs, database schema, Go structs, API surfaces, plugin contracts, LLM integration, and the attack vector engine. Follow it as closely as possible.

---

## 1. Project Overview

**Nyx** is an open-source, locally-run web application penetration testing framework. It orchestrates a suite of security tools in a dependency-aware pipeline, normalizes all output into a shared schema stored in a local database, correlates findings across tools to suggest concrete multi-step attack vectors, and uses a locally-hosted LLM to analyse results, suggest CVEs, and generate pentest report narratives.

Nyx is designed to be:
- **100% local by default** — no telemetry, no cloud, no hosted LLM required; API keys are required for network-exposed serving and host-privileged API operations
- **Web-app focused** — goes well beyond port scanning into SQLi, XSS, SSRF, JWT attacks, CORS, SSTI, XXE, and OAuth misconfigurations
- **Extensible** — plugin-based tool adapter system; community can ship new adapters in any language
- **Cross-platform** — single Go binary + Docker image; runs on Linux, macOS, Windows
- **Dual interface** — CLI for scripting/automation + local web UI for visual analysis and reporting

### Inspiration & Differentiation from METATRON

Nyx was inspired by the METATRON project (github.com/sooryathejas/METATRON), which is a CLI-based pentest assistant for Linux that runs nmap/nikto/whois/dig/whatweb/curl, feeds results to a locally-hosted Qwen LLM, and stores data in a 5-table MariaDB schema.

Nyx improves on this concept in every dimension:

| Dimension | METATRON | Nyx |
|---|---|---|
| Platform | Linux CLI only | Docker + single binary, Linux/macOS/Windows |
| Interface | CLI only | CLI + local web UI |
| Tools | 6 fixed tools | 20+ tools, plugin SDK for more |
| Output normalization | None (raw stdout to LLM) | Universal Finding schema, every tool writes the same format |
| Database | 5-table MariaDB | 9-table SQLite/Postgres with full evidence blobs |
| Web app testing | None | SQLi, XSS, SSRF, JWT, SSTI, XXE, CORS, OAuth |
| LLM | Single fine-tuned Qwen | Any Ollama/llama.cpp/LM Studio model, OpenAI-compatible |
| CVE lookup | DuckDuckGo text search | NVD API v2, OSV.dev, CIRCL, vulners, Exploit-DB |
| Attack chain reasoning | None | Multi-step attack vector engine with confidence scoring |
| Plugin system | None | Subprocess JSON-RPC contract, any language |
| Scope management | None | Whitelist/blacklist, per-tool rate limiting, passive/active modes |
| Reporting | HTML/PDF export | CVSS-scored reports, executive + technical modes, Markdown/HTML/SARIF/PDF |

---

## 2. Design Principles

1. **Scope-first.** The user defines target scope before any scan starts. Hard blocks prevent out-of-scope requests. Every tool adapter respects scope.
2. **Evidence-first.** Every finding stores raw evidence excerpts and full HTTP request/response data in SQLite, while full tool stdout/stderr is retained as session sidecar logs unless lean mode is requested.
3. **Normalize everything.** Every tool, regardless of output format, writes to the same `Finding` struct before anything is persisted or analysed.
4. **DAG, not sequence.** Tools run in dependency order. Phase 1 results unlock Phase 2 tools automatically. Phases parallelize where safe.
5. **LLM augments, rules decide.** The attack vector engine is rule-based first, LLM-enhanced second. Don't rely on LLM reasoning for correctness-critical logic.
6. **One directory per engagement.** Each session directory contains `session.db` plus optional `runs/` sidecar logs, and can be exported as a zip for sharing.
7. **Workload-aware sessions.** `sessions.mode` records scan aggressiveness (`passive`, `active`, `stealth`) while `sessions.workload_mode` records the workload (`dynamic`, `static`, `combined`). Static-only sessions may have zero targets.
8. **Zero required config.** `nyx scan --target example.com` and `nyx audit ./repo --no-llm` should work out of the box with sensible defaults. Everything else is opt-in.
9. **Source-aware correlation.** Combined sessions run source/audit first, dynamic scan second, and a final correlation phase that emits CVEs, graph edges, attack vectors, and static/dynamic confirmations.
10. **Air-gap capable.** Can run fully offline with a local LLM and an offline CVE mirror. No external dependencies required.

---

## 3. Tech Stack

### 3.1 Backend — Go

Go is the primary language for all backend components. Rationale:
- The scanner, API, persistence layer, and CLI share one type system and one release artifact.
- Goroutines + channels map naturally to a parallel DAG scanner where many tools run concurrently.
- A single statically linked binary is ideal for a security tool that needs to run on arbitrary machines.
- `//go:embed` lets the compiled frontend assets be bundled into the binary — one file deployment.
- CGO-free builds with `modernc.org/sqlite` enable true cross-compilation (`GOOS=windows go build` just works).

**Current Go target:** 1.26.4 or newer within the 1.26 line

### 3.2 Complete Dependency List

```
# Config
github.com/spf13/viper

# HTTP router & middleware
net/http                                  # stdlib ServeMux router

# WebSocket (live scan streaming)
github.com/gorilla/websocket

# Database
modernc.org/sqlite                      # pure-Go SQLite, no CGO
# optional future team mode: github.com/jackc/pgx/v5
# optional future query generation: github.com/sqlc-dev/sqlc

# Concurrency
golang.org/x/sync                       # errgroup, semaphore

# LLM client (OpenAI-compatible — works with Ollama, LM Studio, llama.cpp)
github.com/sashabaranov/go-openai

# HTTP client (for CVE lookups, external API calls)
# stdlib net/http is sufficient

# Structured logging
log/slog                                # stdlib

# Config file parsing
# viper handles YAML/TOML/JSON/env

# Report generation
github.com/go-pdf/fpdf                  # PDF reports
html                                    # stdlib, escaped HTML reports

# Testing
github.com/stretchr/testify

# Build/release tooling (dev only)
# goreleaser for cross-platform release builds
```

### 3.3 Frontend — React + TypeScript

```
react 18
typescript 5
vite                        # build tool
react-router-dom v6         # routing within the SPA
@tanstack/react-query       # data fetching + caching
recharts                    # findings dashboard charts
cytoscape                   # attack graph visualization
lucide-react                # icons
```

The frontend is built with `vite build` and the output `dist/` directory is embedded into the Go binary using `//go:embed web/dist`. The stdlib `net/http` server serves it at `/` when `nyx serve` is run.

### 3.4 Database

- **Default:** SQLite via `modernc.org/sqlite` (pure Go, no CGO, one `session.db` per session directory)
- **Supported v1 model:** one directory per session under the configured session root, with `<session-id>/session.db` and optional `<session-id>/runs/*.log`
- **Migrations:** ordered SQL migrations embedded under `internal/db/migrations/`
- **Query layer:** handwritten typed store methods over `database/sql`
- **Future team mode:** PostgreSQL via `pgx/v5` can be evaluated later if multi-user deployments need a shared database.
- **Future query generation:** `sqlc` can be introduced later if query volume or review burden justifies generated accessors.

### 3.5 Plugin System

Subprocess JSON-RPC. Each tool adapter is a standalone binary (any language). Nyx spawns the binary, writes a JSON request to stdin, reads a JSON response from stdout. Configured plugin records store a SHA-256 digest at registration time, and Nyx re-verifies the digest immediately before execution so modified binaries fail as tool runs before a subprocess starts. This is the initial plugin contract. The `hashicorp/go-plugin` (gRPC-based) system can replace this later for performance-critical adapters.

ProjectDiscovery tools (`nuclei`, `httpx`, `subfinder`, `naabu`, `dnsx`) are subprocess adapters in v1. Native Go-library adapters are intentionally deferred: they may reduce installation dependency and stdout parsing fragility, but they also add dependency weight, in-process crash/resource risk, API stability risk, and more maintenance. If revisited, `httpx` is the safest first candidate; `nuclei` and `naabu` should remain deferred until a native adapter pattern proves stable.

### 3.6 Packaging

- **Docker:** Multi-stage build. Stage 1 builds the frontend from a digest-pinned `node:20-alpine` image. Stage 2 builds the Go binary from a digest-pinned `golang:1.26.4-alpine` image. Stage 3 runs on a pinned Debian 13 slim runtime digest with baseline external tools installed and a tool-version smoke script for bundled scanner checks.
- **Single binary option:** `goreleaser` for cross-platform binary releases. The binary embeds the frontend. External tools (nmap etc.) must be installed separately in this mode.

### 3.7 Current V1 Architecture Notes

- API routing uses stdlib `net/http` with explicit auth, CSRF/origin checks for unsafe browser requests, and WebSocket replay at `GET /api/scan/{id}/events`.
- Persistence uses per-session SQLite directories. Flat legacy `<session-id>.db` files are not auto-migrated; operators can manually place a database at `<session-dir>/<session-id>/session.db` if needed.
- Cross-session monitor state uses a global SQLite database at `<state-dir>/nyx-state.db` for monitor configs, runs, and surface changes.
- Full tool stdout/stderr is retained in `<session-id>/runs/` sidecars unless `nyx scan --lean` is used.
- Dynamic, static audit, and combined source-aware workloads share one session database and report pipeline.
- Continuous monitoring creates normal scan sessions, diffs targets/technologies/findings against the monitor baseline, and schedules runs only while `nyx serve` is active.
- Power-feature modules are implemented as explicit operator actions with additive persistence for generated and validated payloads, credential attempts, OSINT records and provider statuses, AD entities/relationships/artifacts, block events, callback evidence, PoC results, and Burp XML/REST bridge state. Active/high-risk actions and callback evidence writes require configured API-key auth through the API, explicit confirmation where applicable, scope checks, and conservative non-destructive behavior.
- Native ProjectDiscovery library integration is deferred. Subprocess adapters remain the supported v1 path because they preserve process isolation and reduce dependency risk.

---

## 4. Project Structure

```
nyx/
├── cmd/
│   ├── root.go              # CLI dispatch, config load, logging bootstrap
│   ├── scan.go              # `nyx scan` command
│   ├── audit.go             # `nyx audit` command group
│   ├── report.go            # `nyx report` — generate report from session
│   ├── sessions.go          # `nyx sessions list/show/delete`
│   ├── plugins.go           # `nyx plugins list/install`
│   ├── llm.go               # `nyx llm` commands
│   └── config.go            # config init/show
│
├── internal/
│   ├── engine/              # sessions, scope, DAG runner, audit runner, events
│   ├── monitor/             # scheduled monitors, immediate runs, diffs, alerts
│   ├── payload/             # advisory payload generation and validation records
│   ├── creds/               # credential record and cautious test orchestration
│   ├── osint/               # OSINT records and local scope seeding
│   ├── activedirectory/     # AD scope checks and BloodHound import helpers
│   ├── evasion/             # request-behavior profile normalization
│   ├── poc/                 # explicit PoC result recording
│   ├── burp/                # Burp XML import/export and bridge helpers
│   │
│   ├── adapters/            # built-in, subprocess, HTTP, and static adapters
│   │   ├── adapter.go       # Adapter interface definition
│   │   ├── recon.go         # subfinder, dnsx, naabu, httpx, whois, nmap, crt.sh
│   │   ├── fingerprint.go   # whatweb, nuclei-tech, GraphQL/OpenAPI, CMS probes
│   │   ├── enumeration.go   # ffuf, arjun, linkfinder, secrets, CORS, buckets
│   │   ├── vulnerability.go # nuclei-vuln, sqlmap, dalfox, SSRF/JWT/OAuth/SSTI/XXE
│   │   └── audit*.go        # static/audit adapters and parsers
│   │
│   ├── db/
│   │   ├── migrations/      # 001_initial.sql, 002_add_cve_matches.sql, ...
│   │   ├── db.go            # connection init, migration runner, session helpers
│   │   └── store.go         # handwritten typed store methods
│   │
│   ├── state/               # global nyx-state.db store for monitor state
│   ├── models/              # canonical sessions, targets, findings, CVEs, graph, reports
│   ├── source/              # static source extractors
│   ├── suppress/            # .nyx-audit-ignore parsing
│   ├── logging/             # slog configuration
│   │
│   ├── llm/
│   │   ├── client.go        # OpenAI-compatible client init (Ollama/llama.cpp/etc)
│   │   ├── context.go       # Builds structured LLM context from DB findings
│   │   ├── analyst.go       # LLM analysis loop: multi-turn, tool calling
│   │   ├── tools.go         # LLM tool definitions (request_scan, lookup_cve, etc)
│   │   └── prompts.go       # System prompts, few-shot examples
│   │
│   ├── cve/
│   │   ├── nvd.go           # NVD API v2 client
│   │   ├── osv.go           # OSV.dev client
│   │   ├── circl.go         # CIRCL CVE search client
│   │   ├── vulners.go       # vulners.com API client
│   │   ├── exploitdb.go     # Exploit-DB offline mirror search
│   │   └── correlator.go    # Match technologies+versions to CVEs
│   │
│   ├── vectors/             # deterministic rules, graph edges, vector scoring
│   │
│   ├── api/
│   │   ├── server.go        # stdlib router, auth middleware, embed.FS serving
│   │   ├── scan_manager.go  # async scan lifecycle and WebSocket replay
│   │   └── web/dist/        # embedded Vite build output
│   │
│   └── report/
│       ├── generator.go     # Report orchestration
│       ├── html.go          # HTML template rendering
│       ├── pdf.go           # PDF generation via go-pdf/fpdf
│       └── templates/       # Go HTML templates
│
├── web/                     # React + TypeScript frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Findings.tsx
│   │   │   ├── Source.tsx
│   │   │   ├── AttackGraph.tsx
│   │   │   ├── LLMChat.tsx
│   │   │   ├── Reports.tsx
│   │   │   ├── Tools.tsx
│   │   │   └── ToolRuns.tsx
│   │   ├── api.ts           # fetch wrappers
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── scripts/                 # integration, Docker, fixture, and smoke scripts
│
├── Dockerfile
├── docker-compose.yml
├── .goreleaser.yaml
├── Makefile
└── README.md
```

---

## 5. Core Data Models (Go Structs)

These are the canonical Go types. The database schema is derived from these, and the handwritten store maps to and from these types.

### 5.1 Finding — The Universal Normalized Type

Every tool adapter, regardless of what the tool outputs, must produce `[]Finding`. This is the central contract.

```go
// internal/models/finding.go

package models

import "time"

type Severity string

const (
    SeverityCritical  Severity = "critical"
    SeverityHigh      Severity = "high"
    SeverityMedium    Severity = "medium"
    SeverityLow       Severity = "low"
    SeverityInfo      Severity = "info"
)

type FindingType string

const (
    FindingTypeVulnerability FindingType = "vulnerability"
    FindingTypeMisconfiguration FindingType = "misconfiguration"
    FindingTypeExposure      FindingType = "exposure"
    FindingTypeInfo          FindingType = "info"
)

type Finding struct {
    ID          string      `json:"id"`           // UUID
    SessionID   string      `json:"session_id"`
    TargetID    string      `json:"target_id"`
    ToolID      string      `json:"tool_id"`      // e.g. "nuclei", "sqlmap"

    Type        FindingType `json:"type"`
    Severity    Severity    `json:"severity"`
    Confidence  float64     `json:"confidence"`   // 0.0–1.0
    CVSSScore   float64     `json:"cvss_score"`   // 0.0–10.0, 0 if unknown

    Title       string      `json:"title"`
    Description string      `json:"description"`
    Remediation string      `json:"remediation"`

    // Where it was found
    URL         string      `json:"url"`
    Parameter   string      `json:"parameter,omitempty"`
    Method      string      `json:"method,omitempty"`   // GET, POST, etc.

    // Evidence
    EvidenceRaw        string `json:"evidence_raw"`        // raw tool stdout/JSON
    EvidenceNormalized string `json:"evidence_normalized"` // tool-agnostic JSON summary

    // Optional HTTP evidence (stored separately in http_evidence table)
    HTTPEvidence *HTTPEvidence `json:"http_evidence,omitempty"`

    // Tags for filtering (e.g. "owasp:A03", "cwe:89", "tech:wordpress")
    Tags        []string    `json:"tags"`

    // CVE matches (populated by CVE correlator, stored in cve_matches table)
    CVEMatches  []CVEMatch  `json:"cve_matches,omitempty"`

    CreatedAt   time.Time   `json:"created_at"`
}

type HTTPEvidence struct {
    FindingID    string `json:"finding_id"`
    RequestRaw   string `json:"request_raw"`
    ResponseRaw  string `json:"response_raw"`
    StatusCode   int    `json:"status_code"`
    ResponseTime int64  `json:"response_time_ms"`
}
```

### 5.2 Target

```go
// internal/models/target.go

package models

import "time"

type Target struct {
    ID        string    `json:"id"`         // UUID
    SessionID string    `json:"session_id"`
    Host      string    `json:"host"`       // hostname or IP
    IP        string    `json:"ip"`
    Port      int       `json:"port"`
    Protocol  string    `json:"protocol"`   // http, https, tcp, udp
    IsAlive   bool      `json:"is_alive"`

    Technologies []Technology `json:"technologies,omitempty"`
    Findings     []Finding    `json:"findings,omitempty"`

    DiscoveredBy string    `json:"discovered_by"` // tool that found this target
    CreatedAt    time.Time `json:"created_at"`
}

type Technology struct {
    ID         string  `json:"id"`
    TargetID   string  `json:"target_id"`
    Name       string  `json:"name"`       // e.g. "WordPress"
    Version    string  `json:"version"`    // e.g. "6.4.2"
    Category   string  `json:"category"`   // e.g. "cms", "language", "server"
    Confidence float64 `json:"confidence"` // 0.0–1.0
    SourceTool string  `json:"source_tool"`
}
```

### 5.3 Session

```go
// internal/models/session.go

package models

import "time"

type SessionStatus string

const (
    SessionStatusPending   SessionStatus = "pending"
    SessionStatusRunning   SessionStatus = "running"
    SessionStatusCompleted SessionStatus = "completed"
    SessionStatusFailed    SessionStatus = "failed"
    SessionStatusCancelled SessionStatus = "cancelled"
)

type ScanMode string

const (
    ScanModePassive ScanMode = "passive" // OSINT only, no active probing
    ScanModeActive  ScanMode = "active"  // full active scanning
    ScanModeStealth ScanMode = "stealth" // active but throttled, evasive timing
)

type Session struct {
    ID          string        `json:"id"`           // UUID
    Name        string        `json:"name"`         // user-defined label
    Status      SessionStatus `json:"status"`
    Mode        ScanMode      `json:"mode"`

    // Scope definition
    TargetInput  string   `json:"target_input"`   // original user input
    InScope      []string `json:"in_scope"`       // allowed hosts/CIDRs
    OutOfScope   []string `json:"out_of_scope"`   // excluded hosts/CIDRs

    // Phases to run (subset of all phases, defaults to all)
    EnabledPhases []string `json:"enabled_phases"`

    // LLM config for this session
    LLMModel    string `json:"llm_model"`    // e.g. "llama3:8b"
    LLMBaseURL  string `json:"llm_base_url"` // e.g. "http://localhost:11434/v1"

    // Stats
    TargetCount  int `json:"target_count"`
    FindingCount int `json:"finding_count"`

    StartedAt   *time.Time `json:"started_at,omitempty"`
    CompletedAt *time.Time `json:"completed_at,omitempty"`
    CreatedAt   time.Time  `json:"created_at"`
}
```

### 5.4 CVEMatch

```go
// internal/models/cve.go

package models

type CVEMatch struct {
    ID              string   `json:"id"`          // UUID
    FindingID       string   `json:"finding_id"`
    TechnologyID    string   `json:"technology_id,omitempty"` // if matched from tech version

    CVEID           string   `json:"cve_id"`      // e.g. "CVE-2021-44228"
    CVSSv3Score     float64  `json:"cvss_v3_score"`
    CVSSv3Vector    string   `json:"cvss_v3_vector"`
    Description     string   `json:"description"`
    AffectedVersion string   `json:"affected_version,omitempty"`
    FixedVersion    string   `json:"fixed_version,omitempty"`
    PatchAvailable  bool     `json:"patch_available"`
    ExploitAvailable bool    `json:"exploit_available"`
    References      []string `json:"references"`
    Source          string   `json:"source"` // "nvd", "osv", "circl", "exploitdb"

    ConfidenceScore float64 `json:"confidence_score"` // how confident the match is
}
```

### 5.5 Attack Vector

```go
// internal/models/attack_vector.go

package models

type AttackVector struct {
    ID          string  `json:"id"` // UUID
    SessionID   string  `json:"session_id"`

    Title       string  `json:"title"`
    Description string  `json:"description"`
    Narrative   string  `json:"narrative"` // human-readable attack story (LLM-generated)

    // OWASP Top 10 category (e.g. "A03:2021 – Injection")
    OWASPCategory string `json:"owasp_category"`

    // CVSS-based severity of the full chain
    Severity    Severity `json:"severity"`
    Confidence  float64  `json:"confidence"` // 0.0–1.0

    // Ordered list of steps in the attack chain
    Steps       []AttackStep `json:"steps"`

    // Finding IDs that are prerequisites for this vector
    PrereqFindingIDs []string `json:"prereq_finding_ids"`

    // Whether the LLM has reviewed and annotated this vector
    LLMReviewed bool   `json:"llm_reviewed"`
    LLMNotes    string `json:"llm_notes"`

    CreatedAt time.Time `json:"created_at"`
}

type AttackStep struct {
    Order       int    `json:"order"`
    Description string `json:"description"`
    FindingID   string `json:"finding_id,omitempty"` // the finding this step exploits
    ToolSuggested string `json:"tool_suggested,omitempty"` // e.g. "sqlmap --level 5"
}
```

### 5.6 ToolRun

```go
// internal/models/tool_run.go

package models

import "time"

type ToolRun struct {
    ID           string    `json:"id"`          // UUID
    SessionID    string    `json:"session_id"`
    TargetID     string    `json:"target_id,omitempty"`
    ToolID       string    `json:"tool_id"`
    Args         []string  `json:"args"`
    StdoutPath   string    `json:"stdout_path"`
    StderrPath   string    `json:"stderr_path"`
    ExitCode     int       `json:"exit_code"`
    DurationMS   int64     `json:"duration_ms"`
    FindingCount int       `json:"finding_count"` // findings produced by this run
    NormalizedAt *time.Time `json:"normalized_at,omitempty"`
    StartedAt    time.Time `json:"started_at"`
}
```

---

## 6. Database Schema (SQL)

Run with golang-migrate. Files in `internal/db/migrations/`.

```sql
-- 001_initial.sql

CREATE TABLE sessions (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'pending',
    mode           TEXT NOT NULL DEFAULT 'active',
    target_input   TEXT NOT NULL,
    in_scope       TEXT NOT NULL DEFAULT '[]',  -- JSON array
    out_of_scope   TEXT NOT NULL DEFAULT '[]',  -- JSON array
    enabled_phases TEXT NOT NULL DEFAULT '[]',  -- JSON array
    llm_model      TEXT NOT NULL DEFAULT '',
    llm_base_url   TEXT NOT NULL DEFAULT '',
    target_count   INTEGER NOT NULL DEFAULT 0,
    finding_count  INTEGER NOT NULL DEFAULT 0,
    started_at     DATETIME,
    completed_at   DATETIME,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE targets (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    host           TEXT NOT NULL,
    ip             TEXT NOT NULL DEFAULT '',
    port           INTEGER NOT NULL DEFAULT 0,
    protocol       TEXT NOT NULL DEFAULT 'https',
    is_alive       BOOLEAN NOT NULL DEFAULT TRUE,
    discovered_by  TEXT NOT NULL DEFAULT '',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_targets_session ON targets(session_id);

CREATE TABLE technologies (
    id           TEXT PRIMARY KEY,
    target_id    TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT '',
    confidence   REAL NOT NULL DEFAULT 0.0,
    source_tool  TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_technologies_target ON technologies(target_id);

CREATE TABLE findings (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id            TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tool_id              TEXT NOT NULL,
    type                 TEXT NOT NULL,
    severity             TEXT NOT NULL,
    confidence           REAL NOT NULL DEFAULT 0.0,
    cvss_score           REAL NOT NULL DEFAULT 0.0,
    title                TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    remediation          TEXT NOT NULL DEFAULT '',
    url                  TEXT NOT NULL DEFAULT '',
    parameter            TEXT NOT NULL DEFAULT '',
    method               TEXT NOT NULL DEFAULT '',
    evidence_raw         TEXT NOT NULL DEFAULT '',
    evidence_normalized  TEXT NOT NULL DEFAULT '',  -- JSON
    tags                 TEXT NOT NULL DEFAULT '[]', -- JSON array
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_findings_session ON findings(session_id);
CREATE INDEX idx_findings_target  ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE http_evidence (
    id             TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    request_raw    TEXT NOT NULL DEFAULT '',
    response_raw   TEXT NOT NULL DEFAULT '',
    status_code    INTEGER NOT NULL DEFAULT 0,
    response_time  INTEGER NOT NULL DEFAULT 0  -- ms
);

CREATE TABLE cve_matches (
    id                TEXT PRIMARY KEY,
    finding_id        TEXT REFERENCES findings(id) ON DELETE CASCADE,
    technology_id     TEXT REFERENCES technologies(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    cvss_v3_score     REAL NOT NULL DEFAULT 0.0,
    cvss_v3_vector    TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    affected_version  TEXT NOT NULL DEFAULT '',
    fixed_version     TEXT NOT NULL DEFAULT '',
    patch_available   BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    references        TEXT NOT NULL DEFAULT '[]', -- JSON array
    source            TEXT NOT NULL DEFAULT '',
    confidence_score  REAL NOT NULL DEFAULT 0.0,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cve_finding ON cve_matches(finding_id);

CREATE TABLE attack_vectors (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    narrative           TEXT NOT NULL DEFAULT '',
    owasp_category      TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL,
    confidence          REAL NOT NULL DEFAULT 0.0,
    steps               TEXT NOT NULL DEFAULT '[]', -- JSON array of AttackStep
    prereq_finding_ids  TEXT NOT NULL DEFAULT '[]', -- JSON array
    llm_reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    llm_notes           TEXT NOT NULL DEFAULT '',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_vectors_session ON attack_vectors(session_id);

CREATE TABLE tool_runs (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id      TEXT REFERENCES targets(id) ON DELETE SET NULL,
    tool_id        TEXT NOT NULL,
    args           TEXT NOT NULL DEFAULT '[]',  -- JSON array
    stdout_path    TEXT NOT NULL DEFAULT '',
    stderr_path    TEXT NOT NULL DEFAULT '',
    exit_code      INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    finding_count  INTEGER NOT NULL DEFAULT 0,
    normalized_at  DATETIME,
    started_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_tool_runs_session ON tool_runs(session_id);

CREATE TABLE llm_analyses (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    model_id        TEXT NOT NULL,
    prompt_summary  TEXT NOT NULL DEFAULT '',
    messages        TEXT NOT NULL DEFAULT '[]', -- JSON array of chat messages
    total_tokens    INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_llm_session ON llm_analyses(session_id);

CREATE TABLE plugins (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    binary     TEXT NOT NULL,
    sha256     TEXT NOT NULL DEFAULT '',
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_plugins_name ON plugins(name);
```

---

## 7. Tool Adapter System

### 7.1 The Adapter Interface

Every tool — whether embedded as a Go library or invoked as a subprocess — implements this interface:

```go
// internal/adapters/adapter.go

package adapters

import (
    "context"
    "nyx/internal/models"
)

// Phase defines which scan phase this adapter runs in.
type Phase string

const (
    PhaseRecon          Phase = "recon"
    PhaseFingerprint    Phase = "fingerprint"
    PhaseEnumerate      Phase = "enumerate"
    PhaseVulnScan       Phase = "vuln_scan"
)

// AdapterInput is what Nyx passes to every adapter.
type AdapterInput struct {
    SessionID string
    Target    models.Target
    Session   models.Session

    // Results from earlier phases available for this adapter to use
    PriorFindings     []models.Finding
    PriorTechnologies []models.Technology
}

// AdapterOutput is what every adapter must return.
type AdapterOutput struct {
    Findings     []models.Finding
    NewTargets   []models.Target     // e.g. subfinder discovers subdomains
    Technologies []models.Technology // e.g. whatweb identifies tech stack
    ToolRun      models.ToolRun
}

// Adapter is the interface all tool adapters must implement.
type Adapter interface {
    // ID returns the unique identifier for this tool (e.g. "nuclei", "sqlmap")
    ID() string

    // Name returns a human-readable name
    Name() string

    // Phase returns which scan phase this adapter belongs to
    Phase() Phase

    // DependsOn returns tool IDs that must complete before this adapter runs.
    // The DAG engine uses this to build the execution graph.
    DependsOn() []string

    // ShouldRun returns true if this adapter should run given prior results.
    // Adapters can skip themselves if there's nothing relevant to scan.
    ShouldRun(input AdapterInput) bool

    // Run executes the tool and returns normalized output.
    Run(ctx context.Context, input AdapterInput) (AdapterOutput, error)
}
```

### 7.2 Registry

```go
// internal/adapters/registry.go

package adapters

var globalRegistry = map[string]Adapter{}

func Register(a Adapter) {
    globalRegistry[a.ID()] = a
}

func Get(id string) (Adapter, bool) {
    a, ok := globalRegistry[id]
    return a, ok
}

func All() []Adapter {
    result := make([]Adapter, 0, len(globalRegistry))
    for _, a := range globalRegistry {
        result = append(result, a)
    }
    return result
}
```

All adapters call `adapters.Register(...)` in their `init()` function so they self-register when imported.

### 7.3 Subprocess Adapter Contract (JSON-RPC)

For tools written outside Go (Python, Ruby, etc.), the subprocess JSON-RPC contract:

**Request (stdin):**
```json
{
  "version": "1",
  "session_id": "uuid",
  "target": {
    "id": "uuid",
    "host": "example.com",
    "ip": "93.184.216.34",
    "port": 443,
    "protocol": "https"
  },
  "prior_findings": [],
  "prior_technologies": [],
  "config": {}
}
```

**Response (stdout):**
```json
{
  "version": "1",
  "findings": [
    {
      "tool_id": "my-custom-tool",
      "type": "vulnerability",
      "severity": "high",
      "confidence": 0.9,
      "title": "SQL Injection in search parameter",
      "description": "...",
      "url": "https://example.com/search?q=test",
      "parameter": "q",
      "method": "GET",
      "evidence_raw": "...",
      "evidence_normalized": "{\"payload\": \"' OR 1=1--\", \"response\": \"...\"}"
    }
  ],
  "new_targets": [],
  "technologies": [],
  "error": null
}
```

Any process that speaks this JSON contract over stdin/stdout is a valid Nyx plugin. The `internal/adapters/subprocess.go` file implements the generic subprocess runner.

Direct CLI adapters must keep operator-provided auth headers and cookies out of
persisted tool-run arguments and live process argv. When a scanner supports raw
request or config files, Nyx writes auth material to a temporary file, passes
only that path to the subprocess, and removes the file after execution.

---

## 8. Tool Pipeline — All Phases

### Phase 1: Reconnaissance
**Goal:** Build a complete map of the attack surface.

| Tool | Integration | What it finds |
|---|---|---|
| `naabu` | Go library | Open ports on all in-scope IPs |
| `subfinder` | Go library | Subdomains via passive sources |
| `dnsx` | Go library | DNS records (A, CNAME, MX, TXT, NS) |
| `httpx` | Go library | Live HTTP/S hosts, status codes, titles, tech detection |
| `nmap` | Go wrapper (Ullaakut/nmap) | Service/version detection on open ports |
| `whois` | subprocess | Domain registrar, ASN, org info |
| `crt.sh` | HTTP API client | Certificate transparency log subdomains |
| `waybackurls` | subprocess | Passive URL discovery from Wayback Machine |

**DependsOn relationships:**
- `subfinder`, `dnsx`, `nmap`, `crt.sh`, `whois` → no dependencies (run first)
- `httpx` → depends on `subfinder`, `naabu` (needs hosts to probe)
- `waybackurls` → depends on `subfinder` (needs subdomains)

### Phase 2: Fingerprinting
**Goal:** Identify technologies, versions, and configurations on all live hosts.

| Tool | Integration | What it finds |
|---|---|---|
| `whatweb` | subprocess | Technology stack fingerprinting |
| `nuclei` (tech templates) | Go library | CMS detection, server info |
| `testssl.sh` | subprocess | TLS versions, cipher suites, cert validity |
| Security headers check | Go stdlib HTTP | Missing/misconfigured headers (CSP, HSTS, X-Frame-Options, etc.) |
| GraphQL introspection | Go stdlib HTTP | Exposed GraphQL schema |
| OpenAPI/Swagger discovery | Go stdlib HTTP | Exposed API documentation endpoints |
| `WPScan` | subprocess | WordPress version, plugins, themes, users |
| `droopescan` | subprocess | Drupal/Silverstripe/Joomla fingerprinting |

**DependsOn:** all Phase 1 adapters

### Phase 3: Enumeration
**Goal:** Discover endpoints, parameters, secrets, and misconfigurations.

| Tool | Integration | What it finds |
|---|---|---|
| `ffuf` / `feroxbuster` | subprocess | Hidden directories and files |
| `arjun` | subprocess | Hidden HTTP parameters |
| `linkfinder` | subprocess | Hidden endpoints extracted from JavaScript files |
| `gitleaks` / `trufflehog` | subprocess | Secrets in JS files, git repos, public pages |
| CORS check | Go stdlib HTTP | Misconfigured CORS (allow-all origins, etc.) |
| S3/GCS enumeration | Go stdlib HTTP | Public cloud storage buckets |

**DependsOn:** all Phase 2 adapters (needs tech fingerprints and live hosts)

### Phase 4: Vulnerability Scanning
**Goal:** Confirm exploitable vulnerabilities. This phase is the most impactful and most dangerous — scope and rate limiting are critical here.

| Tool | Integration | What it finds |
|---|---|---|
| `nuclei` (vuln templates) | subprocess | CVE-matched vulnerability templates |
| `sqlmap` | subprocess | SQL injection in discovered parameters |
| `dalfox` | subprocess | Reflected/stored/DOM XSS |
| `SSRFmap` | subprocess | SSRF in URL parameters and headers |
| JWT review / `jwt_tool` | Go stdlib parser plus optional subprocess | JWT missing expiration, sensitive hash/secret claim paths, alg:none, weak secret, key confusion |
| OAuth checks | Go stdlib HTTP | Open redirect in OAuth callbacks, CSRF |
| Brute force check | Go stdlib HTTP | Strict configured credential validation gated to intentionally vulnerable non-production targets |
| Reflected XSS check | Go stdlib HTTP | Marker reflection in browser-facing seeded query parameters |
| DOM XSS check | Chrome/Chromium via chromedp | Browser-backed DOM marker validation with multiple payload shapes and JavaScript dialog marker observation for seeded query/hash routes gated to intentionally vulnerable non-production targets |
| Stored XSS check | Go stdlib HTTP | Marker submission plus authenticated read-back, gated to intentionally vulnerable non-production targets |
| SQL injection check | Go stdlib HTTP | Bounded boolean/error canaries, including SQLite error markers, in seeded query parameters |
| Open redirect check | Go stdlib HTTP | Controlled external redirects in seeded redirect-like parameters and operator-seeded external redirect URLs |
| File inclusion check | Go stdlib HTTP | Safe local hosts-file marker probes in seeded file/path parameters |
| Command injection check | Go stdlib HTTP | Harmless echo-marker validation gated to intentionally vulnerable non-production targets |
| Upload check | Go stdlib HTTP | Harmless marker-file upload validation on seeded upload routes |
| IDOR check | Go stdlib HTTP | Adjacent-object identifier checks and optional secondary-identity replay |
| Workflow assist | Go stdlib HTTP | Human-assist review hints for seeded high-value forms, business-control parameters, CAPTCHA-protected sensitive workflows, and exposed CAPTCHA answers |
| Observability assist | Go stdlib HTTP | Human-assist review hints for seeded metrics, logging, debug, health, monitoring, and verbose-error surfaces |
| Deserialization assist | Go stdlib HTTP | Human-assist review hints for seeded upload, import, restore, serialized-object, YAML, pickle, and archive surfaces |
| CSP review | Go stdlib HTTP | Human-assist CSP bypass review candidates for seeded CSP-related routes |
| CSRF check | Go stdlib HTTP | Missing token analysis for seeded state-changing forms without submission |
| Weak session check | Go stdlib HTTP | Bounded sampling for predictable session cookies and body tokens |
| SSTI detection | Go stdlib HTTP | Server-side template injection |
| XXE fuzzing | Go stdlib HTTP | Non-exfiltrating XML internal entity marker validation for raw XML and upload-like multipart routes |
| `nikto` | subprocess | Generic web server vulnerability scanner |

**DependsOn:** all Phase 3 adapters (needs parameters, endpoints, and tech info)

---

## 9. DAG Engine

The DAG engine is responsible for:
1. Building a directed acyclic graph of all registered adapters based on their `DependsOn()` declarations.
2. Topologically sorting the graph to determine execution order.
3. Running adapters in parallel where safe (same phase, no cross-dependencies).
4. Propagating results: each adapter receives the accumulated findings and targets from all prior adapters.
5. Respecting rate limits and concurrency caps per adapter.
6. Streaming real-time progress events over WebSocket to the web UI.

```go
// internal/engine/dag.go — pseudocode outline

type DAGEngine struct {
    adapters   []adapters.Adapter
    db         *db.Queries
    ws         *WSBroadcaster // WebSocket event broadcaster
    semaphores map[string]*semaphore.Weighted // per-tool concurrency limits
}

func (e *DAGEngine) Run(ctx context.Context, session models.Session) error {
    // 1. Build dependency graph
    graph := buildGraph(e.adapters)

    // 2. Topological sort → ordered phases
    phases, err := topoSort(graph)

    // 3. For each phase, run all adapters in that phase concurrently
    for _, phase := range phases {
        group, gctx := errgroup.WithContext(ctx)
        for _, adapter := range phase {
            adapter := adapter
            group.Go(func() error {
                // Acquire semaphore for this tool
                sem := e.semaphores[adapter.ID()]
                sem.Acquire(gctx, 1)
                defer sem.Release(1)

                // Build input from accumulated results so far
                input := e.buildInput(session, adapter)

                // Check if adapter wants to run
                if !adapter.ShouldRun(input) {
                    return nil
                }

                // Run
                output, err := adapter.Run(gctx, input)

                // Persist results
                e.persist(output)

                // Broadcast progress event
                e.ws.Broadcast(ScanEvent{ToolID: adapter.ID(), Output: output})

                return err
            })
        }
        group.Wait()
    }

    // 4. After all phases: run CVE correlator and attack vector engine
    e.runCVECorrelator(ctx, session)
    e.runVectorEngine(ctx, session)

    return nil
}
```

---

## 10. LLM Integration

### 10.1 Client Setup

```go
// internal/llm/client.go

package llm

import (
    "github.com/sashabaranov/go-openai"
)

type Config struct {
    BaseURL    string // e.g. "http://localhost:11434/v1" for Ollama
    APIKey     string // "ollama" for Ollama, or real key for OpenAI
    Model      string // e.g. "llama3:8b", "mistral:7b", "gpt-4o"
    MaxTokens  int    // default 4096
    Temperature float32 // default 0.3 for analysis tasks
}

func NewClient(cfg Config) *openai.Client {
    config := openai.DefaultConfig(cfg.APIKey)
    config.BaseURL = cfg.BaseURL
    return openai.NewClientWithConfig(config)
}
```

### 10.2 LLM Tool Definitions (Function Calling)

The LLM is given these tools it can call during the analysis loop:

```go
// internal/llm/tools.go

var LLMTools = []openai.Tool{
    {
        Type: openai.ToolTypeFunction,
        Function: &openai.FunctionDefinition{
            Name:        "request_scan",
            Description: "Request that Nyx run an additional tool scan on a specific target or parameter",
            Parameters: jsonschema.Definition{
                Type: jsonschema.Object,
                Properties: map[string]jsonschema.Definition{
                    "tool_id":    {Type: jsonschema.String, Description: "Tool to run (e.g. sqlmap, dalfox, nuclei)"},
                    "target_url": {Type: jsonschema.String, Description: "Full URL to scan"},
                    "parameter":  {Type: jsonschema.String, Description: "Specific parameter to test"},
                    "extra_args": {Type: jsonschema.Array, Items: &jsonschema.Definition{Type: jsonschema.String}},
                },
                Required: []string{"tool_id", "target_url"},
            },
        },
    },
    {
        Type: openai.ToolTypeFunction,
        Function: &openai.FunctionDefinition{
            Name:        "lookup_cve",
            Description: "Look up details for a specific CVE ID from NVD or OSV",
            Parameters: jsonschema.Definition{
                Type: jsonschema.Object,
                Properties: map[string]jsonschema.Definition{
                    "cve_id": {Type: jsonschema.String, Description: "CVE ID, e.g. CVE-2021-44228"},
                },
                Required: []string{"cve_id"},
            },
        },
    },
    {
        Type: openai.ToolTypeFunction,
        Function: &openai.FunctionDefinition{
            Name:        "search_cves_for_technology",
            Description: "Search for CVEs affecting a specific technology and version",
            Parameters: jsonschema.Definition{
                Type: jsonschema.Object,
                Properties: map[string]jsonschema.Definition{
                    "technology": {Type: jsonschema.String, Description: "Technology name, e.g. Apache, WordPress"},
                    "version":    {Type: jsonschema.String, Description: "Version string, e.g. 2.4.49"},
                },
                Required: []string{"technology"},
            },
        },
    },
    {
        Type: openai.ToolTypeFunction,
        Function: &openai.FunctionDefinition{
            Name:        "get_session_findings",
            Description: "Retrieve all findings for the current session, optionally filtered by severity or type",
            Parameters: jsonschema.Definition{
                Type: jsonschema.Object,
                Properties: map[string]jsonschema.Definition{
                    "severity": {Type: jsonschema.String, Enum: []string{"critical","high","medium","low","info"}},
                    "type":     {Type: jsonschema.String},
                    "tool_id":  {Type: jsonschema.String},
                },
            },
        },
    },
}
```

### 10.3 Context Builder

The context builder assembles a structured JSON summary of the session to include in every LLM prompt. This avoids dumping raw stdout into the LLM.

```go
// internal/llm/context.go

type SessionContext struct {
    SessionID    string                 `json:"session_id"`
    TargetInput  string                 `json:"target_input"`
    Mode         string                 `json:"mode"`
    Targets      []TargetSummary        `json:"targets"`
    Technologies []TechSummary          `json:"technologies"`
    Findings     []FindingSummary       `json:"findings"`
    AttackVectors []AttackVectorSummary `json:"attack_vectors"`
    Stats        SessionStats           `json:"stats"`
}

// Build a context object from the database, suitable for LLM consumption.
// Truncates long evidence fields to stay within context window limits.
func BuildSessionContext(sessionID string, db *db.Queries) (SessionContext, error) { ... }
```

### 10.4 System Prompt

```
You are Nyx, an expert web application penetration testing assistant. You are analysing the results of automated security scans.

Your capabilities:
- Identify patterns across multiple tool outputs that indicate exploitable vulnerabilities
- Suggest concrete multi-step attack chains from existing findings
- Request additional targeted scans if you need more data
- Look up CVEs for discovered technologies and versions
- Write clear, evidence-based vulnerability descriptions and remediation steps

Your constraints:
- Only suggest attacks against targets within the defined scope
- Base all conclusions on actual scan evidence, not assumptions
- When confidence is low, say so explicitly
- Prioritise findings by real-world exploitability, not just CVSS score
- Remediation advice must be specific to the exact version and config found

Output format:
- Use structured JSON for tool calls
- Use clear Markdown for analysis text
- Label severity as: critical / high / medium / low / info
- Assign confidence as a percentage

The current session context is provided as a JSON object.
```

---

## 11. CVE Intelligence Engine

### 11.1 Sources

| Source | API | What it covers |
|---|---|---|
| NVD API v2 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Authoritative CVE database with CVSS v3 |
| OSV.dev | `https://api.osv.dev/v1/query` | Open source package vulnerabilities |
| CIRCL CVE Search | `https://cve.circl.lu/api/` | Fast CVE search, good for version matching |
| vulners.com | `https://vulners.com/api/v3/` | Aggregated CVE + exploit data |
| Exploit-DB | Offline mirror/CSV | Known public exploits |
| GitHub Security Advisories | `https://api.github.com/advisories` | Package-level advisories |

### 11.2 Correlator Logic

The CVE correlator runs after all scan phases complete. For each `Technology` record with a non-empty `Version`:

1. Query NVD CPE match API: `GET /rest/json/cves/2.0?cpeName=cpe:2.3:a:{vendor}:{product}:{version}:*`
2. Query OSV.dev: `POST /v1/query` with package name and version
3. For each CVE found:
   - Check if CVSS v3 score is available; fall back to v2
   - Check if an Exploit-DB entry exists for this CVE
   - Score confidence: exact version match = 1.0, version range match = 0.8, product match only = 0.4
4. Create `CVEMatch` records and link to the corresponding `Technology` or `Finding`
5. For CVEs with `exploit_available = true` and score ≥ 7.0, automatically create a draft `AttackVector`

---

## 12. Attack Vector Engine

### 12.1 Architecture

The attack vector engine runs in two passes:

**Pass 1 — Rule-based:** Evaluate predefined rules against the findings database. Each rule defines prerequisite findings (by type, tool, parameter, or tag) and a resulting attack chain template. Fast, deterministic, high confidence.

**Pass 2 — LLM augmentation:** Feed all rule-generated attack vectors plus unmatched high/critical findings to the LLM. Ask it to: (a) validate and refine existing vectors, (b) identify additional attack chains that rules didn't catch, (c) write the human-readable `narrative` field.

### 12.2 Rule Format

```go
// internal/vectors/rules.go

type Rule struct {
    ID           string
    Title        string
    OWASPCategory string
    Severity     models.Severity
    BasedConfidence float64

    // All conditions must match for the rule to fire
    Conditions   []Condition
    // The attack chain template to emit
    ChainTemplate AttackChainTemplate
}

type Condition struct {
    // Match findings by these criteria (AND within a Condition, OR across Conditions)
    ToolID    string  // empty = any tool
    FindingType models.FindingType
    SeverityMin models.Severity
    URLContains  string
    TagContains  string
    ParameterSet bool // true = a parameter must be identified
}
```

### 12.3 Example Rules

```go
var DefaultRules = []Rule{
    {
        ID: "xss-no-csp",
        Title: "Reflected XSS with no Content-Security-Policy",
        OWASPCategory: "A03:2021 – Injection",
        Severity: models.SeverityHigh,
        BaseConfidence: 0.85,
        Conditions: []Condition{
            {ToolID: "dalfox", FindingType: models.FindingTypeVulnerability},
            {ToolID: "header-check", TagContains: "missing-csp"},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Identify the reflected XSS parameter found by dalfox",
                "Craft a payload to steal session cookies (no CSP to block inline scripts)",
                "Deliver via phishing link or stored reference",
                "Receive cookies at attacker-controlled endpoint",
            },
        },
    },
    {
        ID: "ssrf-cloud-metadata",
        Title: "SSRF to cloud instance metadata service",
        OWASPCategory: "A10:2021 – Server-Side Request Forgery",
        Severity: models.SeverityCritical,
        BaseConfidence: 0.95,
        Conditions: []Condition{
            {ToolID: "ssrfmap", TagContains: "cloud-metadata"},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Exploit SSRF vulnerability found by SSRFmap",
                "Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "Extract temporary AWS IAM credentials from response",
                "Use credentials to enumerate/exfiltrate cloud resources",
            },
        },
    },
    {
        ID: "jwt-weak-secret",
        Title: "JWT with crackable HS256 secret",
        OWASPCategory: "A02:2021 – Cryptographic Failures",
        Severity: models.SeverityCritical,
        BaseConfidence: 0.9,
        Conditions: []Condition{
            {ToolID: "jwt_tool", TagContains: "weak-secret"},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Crack HS256 JWT secret using hashcat/jwt_tool wordlist attack",
                "Forge a new JWT with elevated role claim (e.g. admin:true, role:admin)",
                "Replace Authorization header with forged token",
                "Access privileged endpoints",
            },
        },
    },
    {
        ID: "sqli-unauth",
        Title: "SQL injection in unauthenticated endpoint",
        OWASPCategory: "A03:2021 – Injection",
        Severity: models.SeverityCritical,
        BaseConfidence: 0.92,
        Conditions: []Condition{
            {ToolID: "sqlmap", FindingType: models.FindingTypeVulnerability},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Confirm injectable parameter with sqlmap --level 3",
                "Enumerate databases: sqlmap --dbs",
                "Dump target tables: sqlmap -D <db> --tables, then --dump",
                "If stack queries allowed: attempt OS shell via --os-shell",
            },
        },
    },
    {
        ID: "exposed-admin-panel-weak-auth",
        Title: "Exposed admin panel with default or brute-forceable credentials",
        OWASPCategory: "A07:2021 – Identification and Authentication Failures",
        Severity: models.SeverityHigh,
        BaseConfidence: 0.7,
        Conditions: []Condition{
            {ToolID: "ffuf", TagContains: "admin-panel"},
            {TagContains: "no-lockout"},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Admin panel found with no rate limiting or account lockout",
                "Attempt credential stuffing with common admin wordlist",
                "On success: enumerate application internals, upload webshell if file upload present",
            },
        },
    },
    {
        ID: "cors-wildcard-credentials",
        Title: "CORS misconfiguration with wildcard + credentials",
        OWASPCategory: "A05:2021 – Security Misconfiguration",
        Severity: models.SeverityHigh,
        BaseConfidence: 0.88,
        Conditions: []Condition{
            {TagContains: "cors-wildcard-credentials"},
        },
        ChainTemplate: AttackChainTemplate{
            Steps: []string{
                "Host attacker-controlled page with cross-origin fetch to target API",
                "Browser sends request with victim's cookies (credentials:include)",
                "Read sensitive API response — account data, tokens, PII",
            },
        },
    },
}
```

---

## 13. REST API Surface

The stdlib `net/http` router exposes these endpoints. All responses are JSON. Authentication is a local API key stored in the Nyx config file. Nyx refuses non-loopback serving without an API key, and host-privileged API operations such as plugin management, API source scans, and LLM endpoint probing require API-key authentication. LLM base URLs are validated when accepted from API/CLI input and again immediately before OpenAI-compatible completion requests, so persisted session URLs must still satisfy `NYX_LLM_ALLOWED_HOSTS` at invocation time; LLM clients also reject disallowed redirect targets and connect-time DNS results. Burp REST base URLs are loopback-only by default and remote/private hosts must be explicitly allowed with `NYX_BURP_ALLOWED_HOSTS` or `power.burp.allowed_hosts`; Burp XML imports skip hosts outside the selected session scope, and Burp REST clients apply the same redirect and connect-time DNS guardrails. Power-feature PoC active validation re-checks persisted finding URLs and redirect targets against the selected session scope before marker requests are sent. Header authentication uses `X-Nyx-API-Key` or `Authorization: Bearer`; query-string API keys are rejected. Failed authentication uses exponential backoff keyed by client address and a short fingerprint of the presented credential, then clears after successful authentication or a long idle reset. Unsafe browser/API methods reject cross-origin `Origin` headers, and JSON mutation endpoints require `Content-Type: application/json` so simple form posts or missing content types cannot reach handlers; plugin upload and Burp XML import are explicit non-JSON exceptions. Session database paths require strict session IDs and absolute path containment under the configured sessions directory before filesystem access. The HTTP server uses finite read/header/idle timeouts plus a non-streaming request timeout; scan event WebSocket routes are exempt so live progress streams can remain open while scans run. Shutdown stops monitor scheduling, cancels active scan contexts, and waits for scan goroutines to persist their final cancelled state; resumable scan replay is deferred. Effective config and health responses return readiness/configured indicators instead of absolute local filesystem paths. The browser console obtains an opaque HttpOnly same-origin session cookie through the login endpoint. Browser session tokens are stored in server memory with a 12-hour TTL, pruned periodically, and intentionally invalidated on server restart. Direct TLS requests automatically receive `Secure` cookies, and HTTPS reverse-proxy deployments can force secure cookies with `NYX_SECURE_COOKIES=true` or `server.secure_cookies: true`.

```
POST   /api/auth/login              Exchange API key for HttpOnly browser session cookie
POST   /api/auth/logout             Clear browser session cookie
POST   /api/scan/start              Start a new scan session
POST   /api/scan/{id}/stop          Cancel a running scan
GET    /api/scan/{id}/status        Live scan status (polling fallback)

GET    /api/sessions                List all sessions
GET    /api/sessions/{id}           Get session details
DELETE /api/sessions/{id}           Delete a session and all its data

GET    /api/sessions/{id}/targets   List all targets for a session
GET    /api/sessions/{id}/findings  List findings (filters: severity, type, tool, page, limit)
GET    /api/sessions/{id}/vectors   List attack vectors
GET    /api/sessions/{id}/cves      List CVE matches
GET    /api/sessions/{id}/stats     Aggregated stats (severity counts, tool coverage, etc.)

POST   /api/sessions/{id}/llm/chat  Send a message to the LLM analyst (multi-turn)
POST   /api/sessions/{id}/llm/analyse  Trigger full LLM analysis of the session
GET    /api/sessions/{id}/llm/history  Get LLM conversation history

GET    /api/sessions/{id}/report    Generate and return report (query param: format=html|pdf|md)

GET    /api/monitor/configs         List monitor configs
POST   /api/monitor/configs         Create a monitor config (requires configured API key)
GET    /api/monitor/configs/{id}    Get one monitor config
PUT    /api/monitor/configs/{id}    Update a monitor config (requires configured API key)
DELETE /api/monitor/configs/{id}    Delete a monitor config (requires configured API key)
POST   /api/monitor/configs/{id}/run  Run a monitor immediately (requires configured API key)
GET    /api/monitor/runs?config_id= List monitor runs
GET    /api/monitor/runs/{id}/changes  List surface changes for a run
PUT    /api/monitor/changes/{id}/alert-sent  Mark a change alerted

POST   /api/sessions/{id}/findings/{finding_id}/generate-payloads
GET    /api/sessions/{id}/findings/{finding_id}/payloads
GET    /api/sessions/{id}/payloads
POST   /api/sessions/{id}/payloads/{payload_id}/validate
GET    /api/sessions/{id}/credentials
POST   /api/sessions/{id}/credentials/test
GET    /api/sessions/{id}/osint
POST   /api/sessions/{id}/osint/run
GET    /api/sessions/{id}/ad/entities
GET    /api/sessions/{id}/ad/relationships
POST   /api/sessions/{id}/ad/kerberoast
POST   /api/sessions/{id}/ad/bloodhound/import
GET    /api/sessions/{id}/block-events
POST   /api/sessions/{id}/findings/{finding_id}/poc/run
GET    /api/sessions/{id}/poc-results
GET    /api/sessions/{id}/provider-statuses
GET    /api/sessions/{id}/callbacks
GET    /api/sessions/{id}/callbacks/{token}
POST   /api/sessions/{id}/burp/import
GET    /api/sessions/{id}/burp/export/scope
GET    /api/sessions/{id}/burp/export/findings
GET    /api/sessions/{id}/burp/status
POST   /api/sessions/{id}/burp/push-scope
POST   /api/sessions/{id}/burp/pull-issues
GET    /api/burp/status

GET    /api/tools                   List all registered tool adapters
GET    /api/health                  Health check (DB connected, LLM reachable, tools available)

GET    /api/scan/{id}/events       WebSocket — real-time scan events
```

The callback recording endpoint is a privileged evidence write path and requires configured API-key authentication; callback rows are evidence records, not an unauthenticated public OAST collector.

### WebSocket Event Format

```json
{
  "type": "tool_started",   // queued | running | tool_started | tool_completed | tool_error | phase_started | phase_completed | finding_found | auth_status | failed | completed | cancelled
  "session_id": "uuid",
  "tool_id": "nuclei",
  "phase": "vuln_scan",
  "status": "running",
  "message": "tool-specific status",
  "finding_count": 1,
  "duration_ms": 1234,
  "at": "2025-01-15T14:23:01Z"
}
```

`auth_status` events report auth validation and refresh lifecycle states such as
`valid`, `invalid`, `refreshing`, `refreshed`, `failed`, and `skipped`.

---

## 14. CLI Commands

```
nyx scan --target <host/CIDR/URL>     Start a scan (most common command)
         --source /path/to/repo       Source-aware combined mode when target is present; static-only when target is absent
         --name "Engagement name"      Label for this session
         --mode passive|active|stealth Scan mode (default: active)
         --phases recon,fingerprint,...  Limit to specific phases
         --tools nuclei,sqlmap,...       Limit to specific tools
         --out-of-scope host1,host2     Exclude from scope
         --route-seed-file routes.txt   Seed authenticated/deep route checks
         --auth-profile auth.json       Generic form or JSON login profile
         --auth-header "Name: value"    Static auth header
         --auth-cookie "name=value"     Static auth cookie header
         --llm-model llama3:8b          LLM model to use
         --llm-url http://localhost:11434/v1
         --no-llm                       Skip LLM analysis
         --concurrency 5               Max concurrent tools (default: 3)
         --rate-limit 100              Max requests/second globally

nyx audit <path>                      Run built-in static audit against source code
          --name "Audit name"         Label for this static session
          --format terminal|json|sarif|html|md
          --output audit.sarif        Output file (default: stdout for report formats)
          --fail-on critical|high|medium|low
          --diff path1,path2          Restrict audit findings to changed paths
          --tools audit/semgrep,...   Limit static adapters
          --offline                   Prefer offline-safe audit execution
          --no-llm                    Skip audit triage/dataflow/narrative LLM passes
nyx audit findings <session-id>       List audit findings from a session
nyx audit report <session-id>         Generate a report from an audit session
nyx audit tools                       List built-in and external audit adapters

nyx serve                             Start the web UI and API server
         --port 6767                  (default: 6767)
         --host 127.0.0.1            (default: localhost only)

nyx sessions list                     List all sessions
nyx sessions show <id>                Show session details
nyx sessions delete <id>              Delete a session

nyx monitor create --target ...       Create a recurring monitor config
nyx monitor list                       List monitor configs
nyx monitor enable <config-id>         Enable scheduling for a monitor
nyx monitor disable <config-id>        Disable scheduling for a monitor
nyx monitor run <config-id>            Run a monitor immediately
nyx monitor changes <config-id>        Show stored surface changes
nyx monitor delete <config-id>         Delete a monitor config and run history

nyx payloads generate <session-id> --finding <id>
nyx payloads validate <session-id> --payload <id> --confirm --enabled=true
nyx payloads list <session-id>
nyx creds test <session-id> --mode correlate
nyx creds test <session-id> --mode defaults --url <login-url> --username <user> --password <pass> --confirm
nyx creds list <session-id>
nyx osint run <session-id> --providers github,shodan,securitytrails
nyx osint list <session-id>
nyx ad enum <session-id> --domain example.local
nyx ad kerberoast <session-id> --username svc-http --confirm
nyx ad bloodhound export <session-id>
nyx poc run <session-id> --finding <id> --confirm --active=true
nyx poc list <session-id>
nyx burp status <session-id>
nyx burp push-scope <session-id>
nyx burp pull-issues <session-id>
nyx burp export scope <session-id> --output scope.xml

nyx report <session-id>               Generate report
          --format html|pdf|md|sarif  Output format (default: html)
          --output report.html        Output file (default: stdout)
          --mode executive|technical  Report depth (default: technical)

nyx llm chat <session-id>             Interactive LLM chat about a session
nyx llm analyse <session-id>          Run full LLM analysis and print results

nyx plugins list                      List available adapters
nyx plugins install <path>            Register a subprocess plugin binary

nyx config init                       Create default config file (~/.nyx/config.yaml)
nyx config show                       Show current config
```

Audit adapters normalize native output from Semgrep, Bandit, gosec,
govulncheck, npm audit, retire.js, safety, Brakeman, SpotBugs, Psalm,
trufflehog, gitleaks, and grype into findings or dependency CVE records.
Unknown JSON-shaped output falls back to generic traversal.

---

## 15. Web UI Pages

The frontend is a React SPA embedded in the Go binary. Routes:

### 15.1 Dashboard (`/`)
- Active and recent sessions list
- Quick-start new scan form (target input, mode selector, name)
- Global stats: total findings by severity across all sessions
- Combined-mode sessions show source analysis, audit, dynamic, and correlation
  progress tracks through the same scan event stream.

### 15.1a Monitor (`/monitor`)
- Create lightweight recurring monitor configs with target, schedule, phases,
  and alert triggers.
- List enabled/disabled configs with next run, baseline session, and target.
- Trigger immediate monitor runs, open generated sessions, and review run
  history.
- Display persisted surface changes grouped by severity and change type.

### 15.1b Power Features (`/sessions/:id/power`)
- Consolidated operator surface for payloads, credentials, OSINT provider
  status, AD/internal records, PoC, callbacks, Burp bridge actions, and
  evasion/block-event records.
- Advanced actions stay manual and visible; the UI does not run credential,
  PoC, Burp REST, or AD actions implicitly.
- Finding-scoped payload and PoC controls require an explicit finding ID or use
  the first finding only as a convenience for local fixture checks.
- Payload validation is limited to fixture-safe marker classes. Credential
  testing is lockout-aware, paced, scope-checked, requires explicit
  operator-supplied usernames and passwords for active login attempts, and
  stores redacted passwords unless plaintext storage is explicitly enabled in
  config.

### 15.2 Session Detail (`/sessions/:id`)
- Session metadata (target, mode, duration, status)
- Live scan progress: phase tracker, tool status indicators, real-time finding counter (via WebSocket)
- Findings table: sortable by severity/tool/type, filterable, paginated
- Severity distribution chart (Recharts donut)
- Tool coverage matrix (which tools ran, how many findings each produced)

### 15.3 Attack Graph (`/sessions/:id/graph`)
- Route-level in-progress placeholder while the attack path workspace is redesigned.
- Labelled source/audit graph edges (`enables`, `amplifies`, `requires`, `confirms`) remain exposed by the API and helper code for the future UI.
- Attack vector, graph edge, target, finding, and source finding data remain available through API surfaces outside the hidden page UI.

### 15.4 Findings (`/sessions/:id/findings`)
- Full findings table with all fields
- Expandable rows showing raw evidence, HTTP request/response, CVE matches
- Bulk actions: export selected, change severity, add notes
- Filters: severity, origin, status, type, tool, OWASP category, has CVE, has exploit
- Origin badges distinguish dynamic, static, and static + dynamic findings.
- Finding triage status is server-validated and limited to `open`,
  `confirmed`, `false-positive`, `suppressed`, and `wont-fix`.
- Audit fields include status, notes, code context, and flow summary.

### 15.4a Source (`/sessions/:id/source`)
- Source finding table with context snippets, language/framework, kind, method,
  file path, line number, and risky-kind severity styling.
- Static + dynamic badges mark source findings confirmed by dynamic evidence.
- Filters support source kind and static-only versus static + dynamic state.

### 15.5 LLM Chat (`/sessions/:id/llm`)
- Chat interface with the LLM analyst
- Shows full conversation history
- LLM tool calls are rendered visibly (e.g. "Running sqlmap against /search?q=...")
- Suggested prompts:
  - "Summarise the most critical findings"
  - "What attack chain should I try first?"
  - "Write an executive summary for this session"
  - "Are there any CVEs I should confirm manually?"

### 15.6 Reports (`/sessions/:id/report`)
- Report preview (HTML rendered in iframe)
- Toggle: executive summary / full technical report
- Download as PDF, Markdown, HTML, or SARIF
- Report sections:
  - Executive summary (LLM-generated narrative)
  - Scope and methodology
  - Static source findings and audit coverage
  - Critical & high findings (full detail)
  - Medium & low findings (summary table)
  - Attack vectors (with step-by-step chains and graph-derived paths)
  - CVE matches with patch availability and dependency package metadata
  - Tool coverage
  - Dismissed and suppressed audit findings
  - Cross-confirmed static/dynamic findings
  - Remediation roadmap (prioritised by severity)
  - Appendix: raw tool output

---

## 16. Configuration File

Default location: `~/.nyx/config.yaml`

```yaml
# Nyx configuration

# LLM settings
llm:
  provider: ollama          # ollama | openai | lmstudio | custom
  base_url: http://localhost:11434/v1
  api_key: ollama           # "ollama" for local, real key for cloud
  model: llama3:8b
  max_tokens: 4096
  temperature: 0.3

# Database settings
database:
  session_dir: ~/.nyx/sessions

# Web server settings
server:
  host: 127.0.0.1
  port: 6767
  api_key: ""               # Empty = no auth for loopback-only local use. Required for network access and privileged API operations. Never accepted from query strings.
  secure_cookies: false     # Set true when HTTPS is terminated before Nyx.

# Logging settings
logging:
  level: info               # debug | info | warn | error
  format: text              # text | json

# Default scan settings
scan:
  mode: active
  concurrency: 4
  rate_limit: ""

# CVE intelligence
cve:
  enabled: true
  sources:
    - nvd
    - osv
    - circl
  nvd_api_key: ""           # Optional — higher rate limits with key
  cache_ttl: 86400          # seconds to cache CVE data

# Power-feature settings. All secrets are redacted in effective config/API/UI.
power:
  providers:
    github_token: ""
    shodan_api_key: ""
    securitytrails_api_key: ""
  burp:
    base_url: ""
    api_key: ""
    allowed_hosts: []       # optional non-loopback Burp REST host allowlist
  callbacks:
    provider: builtin       # builtin | interactsh | burp
    interactsh_url: ""
  credentials:
    max_attempts_per_user: 3
    delay_seconds: 3
    store_plaintext: false
  active_validation:
    enabled: false

# Tool paths (auto-detected if in PATH)
tools:
  nmap: /usr/bin/nmap
  sqlmap: /usr/bin/sqlmap
  ffuf: /usr/local/bin/ffuf
  dalfox: /usr/local/bin/dalfox
  testssl: /opt/testssl.sh/testssl.sh
  wpscan: /usr/local/bin/wpscan

# Plugin directories
plugins:
  dirs:
    - ~/.nyx/plugins/
```

---

## 17. Scope Validation

Scope validation must run before every network request made by any tool. It lives in `internal/engine/scope.go`.

```go
type ScopeChecker struct {
    inScope    []*net.IPNet  // parsed CIDRs
    inHosts    []string       // specific in-scope hostnames
    outScope   []*net.IPNet
    outHosts   []string
}

// IsInScope returns true if the host/IP is within scope.
// Returns false and an explanation if not.
func (s *ScopeChecker) IsInScope(host string) (bool, string) { ... }
```

Any adapter that attempts to connect to an out-of-scope host must receive an error from the scope checker, log it, and return zero findings. The DAG engine logs all scope violations.

---

## 18. Error Handling & Logging

- Use Go's stdlib `log/slog` throughout (structured JSON logging).
- Log level configurable: `debug | info | warn | error`
- Tool adapter failures are non-fatal: log the error, write stderr to the run sidecar log when log retention is enabled, continue the scan.
- A scan fails (status = "failed") only if the session-level context is cancelled or an unrecoverable DB error occurs.
- Every tool run writes a `ToolRun` record regardless of success or failure.

---

## 19. Testing Strategy

- **Unit tests** for: scope checker, DAG topological sort, Finding normalization helpers, CVE correlator matching logic, attack vector rule evaluation.
- **Adapter tests** use fixture files: each adapter has a `testdata/` directory with sample raw tool output. Tests verify the adapter produces the expected normalized findings from the fixture.
- **Integration tests** are opt-in with `NYX_RUN_INTEGRATION=1`: start the deterministic Go vulnerable fixture, run dynamic scans, static audits, combined source-aware scans, report generation, and lean sidecar-log checks.
- **Power integration tests** are opt-in with `NYX_RUN_POWER_INTEGRATION=1`: exercise safe payload validation, credential redaction, provider skip states, PoC records, and power report sections.
- **Browser smoke tests** are opt-in with `NYX_RUN_BROWSER_SMOKE=1`: start a fixture-backed UI session, drive dashboard/findings/power/reports/attack-path pages in Chromium, fail on console errors, and write screenshots to `/tmp/nyx-browser-*.png`.
- **Linux full-tool validation** is opt-in with `NYX_RUN_LINUX_FULL=1`: after external tools are installed, run the fixture-backed dynamic, lean, audit, and combined paths with broader subprocess adapter coverage. `scripts/tool-version-smoke.sh linux-full` reports scanner versions and can be made strict with `NYX_TOOL_SMOKE_STRICT=1`.
- **Benchmark validation** is opt-in with `NYX_RUN_BENCHMARKS=1`: run DVWA and OWASP Juice Shop against profile-owned credentials, route seeds, and expected mappings. The summary gate enforces the accepted Linux VM baseline by default: DVWA must cover at least 14 expected items, Juice Shop must cover at least 15 expected items, and benchmark tool runs must have zero nonzero exits unless an explicit local override is set.
- **Human-assist evidence** should remain structured and non-decisive: partial observability/deserialization findings include response status, content type, response size, redacted short excerpts, and relevant form metadata where available, but they do not claim confirmed exploitability without deterministic validation.
- **API tests** use `net/http/httptest` to test all REST endpoints against an in-memory SQLite DB.

Future enhancement modules are tracked separately in
`docs/nyx-power-features-spec.md`, with implementation-ready plans under
`docs/power-feature-plans/`.

---

## 20. Docker Setup

```dockerfile
# Dockerfile

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS backend
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/api/web/dist ./internal/api/web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/nyx .

FROM debian:13-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8
RUN if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/g' /etc/apt/sources.list.d/debian.sources; \
    fi \
  && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils ffuf nikto nmap python3 python3-pip \
    sqlmap whatweb whois \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=backend /out/nyx /usr/local/bin/nyx
COPY scripts/tool-version-smoke.sh /usr/local/bin/nyx-tool-version-smoke
EXPOSE 6767
ENTRYPOINT ["nyx"]
CMD ["serve", "--host", "0.0.0.0", "--port", "6767"]
```

```yaml
# docker-compose.yml
services:
  nyx:
    build: .
    ports:
      - "6767:6767"
    volumes:
      - nyx-data:/root/.nyx/data
      - ./config.yaml:/root/.nyx/config.yaml
    environment:
      - NYX_LLM_BASE_URL=http://ollama:11434/v1
      - NYX_LLM_MODEL=llama3:8b

  ollama:
    image: ollama/ollama:latest@sha256:72c60eb9e115e24078864c00274dc067fff2217b105918409856031cca7a7e92
    volumes:
      - ollama-data:/root/.ollama
    ports:
      - "127.0.0.1:11434:11434"

volumes:
  nyx-data:
  ollama-data:
```

---

## 21. Makefile

```makefile
.PHONY: build dev test lint web clean

build:
	cd web && npm run build
	go build -o bin/nyx ./cmd/nyx

dev:
	# Run Go API server and Vite dev server in parallel
	air &    # air is a Go hot-reload tool
	cd web && npm run dev

test:
	go test ./... -v

test-integration:
	NYX_RUN_INTEGRATION=1 ./scripts/integration-smoke.sh

lint:
	golangci-lint run
	cd web && npm run lint

web:
	cd web && npm run build

sqlc:
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "sqlc not installed; handwritten store is currently used"; fi

migrate-up:
	go run ./cmd/nyx/main.go migrate up

clean:
	rm -rf bin/ web/dist/
```

---

## 22. Build Order Recommendation for AI Coding Assistant

Build in this order to have working, testable code at each step:

1. **Data models** (`internal/models/`) — all Go structs, no deps
2. **Database** (`internal/db/`) — migrations, session helpers, handwritten store
3. **Scope checker** (`internal/engine/scope.go`) — test independently
4. **Adapter interface + registry** (`internal/adapters/adapter.go`, `registry.go`)
5. **Subprocess runner** (`internal/adapters/subprocess.go`) — generic JSON-RPC runner
6. **First adapters** — start with built-in probes and subprocess adapters
7. **DAG engine** (`internal/engine/dag.go`, `scheduler.go`) — wire up with first adapters
8. **REST API** (`internal/api/`) — CRUD for sessions/findings, WebSocket
9. **CVE correlator** (`internal/cve/`)
10. **Attack vector engine** (`internal/vectors/`)
11. **LLM client + analyst** (`internal/llm/`)
12. **CLI commands** (`cmd/`) — scan, serve, report
13. **Remaining adapters** — add one at a time
14. **Report generator** (`internal/report/`)
15. **React frontend** (`web/`) — build after API is stable
16. **Docker + embed.FS** — bundle frontend into binary last

---

## 23. Security & Legal Notes

**Include prominently in README and CLI:**

> Nyx is intended exclusively for authorized penetration testing, security research, and CTF challenges. Only use Nyx against systems you own or have explicit, written permission to test. Unauthorized scanning or exploitation of systems is illegal in most jurisdictions. The authors accept no responsibility for misuse.

---

*End of Nyx Project Specification — Version 1.0*
