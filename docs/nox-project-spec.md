# Nox — Web Application Penetration Testing Framework
## Complete Project Specification & Build Document

> **Purpose of this document:** This is a full technical specification for an AI coding assistant to use as the primary reference when building the Nox project. It covers architecture, tech stack rationale, all component designs, database schema, Go structs, API surfaces, plugin contracts, LLM integration, and the attack vector engine. Follow it as closely as possible.

---

## 1. Project Overview

**Nox** is an open-source, locally-run web application penetration testing framework. It orchestrates a suite of security tools in a dependency-aware pipeline, normalizes all output into a shared schema stored in a local database, correlates findings across tools to suggest concrete multi-step attack vectors, and uses a locally-hosted LLM to analyse results, suggest CVEs, and generate pentest report narratives.

Nox is designed to be:
- **100% local by default** — no telemetry, no cloud, no API keys required
- **Web-app focused** — goes well beyond port scanning into SQLi, XSS, SSRF, JWT attacks, CORS, SSTI, XXE, and OAuth misconfigurations
- **Extensible** — plugin-based tool adapter system; community can ship new adapters in any language
- **Cross-platform** — single Go binary + Docker image; runs on Linux, macOS, Windows
- **Dual interface** — CLI for scripting/automation + local web UI for visual analysis and reporting

### Inspiration & Differentiation from METATRON

Nox was inspired by the METATRON project (github.com/sooryathejas/METATRON), which is a CLI-based pentest assistant for Linux that runs nmap/nikto/whois/dig/whatweb/curl, feeds results to a locally-hosted Qwen LLM, and stores data in a 5-table MariaDB schema.

Nox improves on this concept in every dimension:

| Dimension | METATRON | Nox |
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
8. **Zero required config.** `nox scan --target example.com` and `nox audit ./repo --no-llm` should work out of the box with sensible defaults. Everything else is opt-in.
8. **Air-gap capable.** Can run fully offline with a local LLM and an offline CVE mirror. No external dependencies required.

---

## 3. Tech Stack

### 3.1 Backend — Go

Go is the primary language for all backend components. Rationale:
- The ProjectDiscovery security tool suite (nuclei, httpx, subfinder, naabu, dnsx) is written in Go and publishes importable Go packages — embed them as libraries rather than shelling out and parsing stdout.
- Goroutines + channels map naturally to a parallel DAG scanner where many tools run concurrently.
- A single statically linked binary is ideal for a security tool that needs to run on arbitrary machines.
- `//go:embed` lets the compiled frontend assets be bundled into the binary — one file deployment.
- CGO-free builds with `modernc.org/sqlite` enable true cross-compilation (`GOOS=windows go build` just works).

**Minimum Go version:** 1.22

### 3.2 Complete Dependency List

```
# CLI & config
github.com/spf13/cobra
github.com/spf13/viper

# HTTP router & middleware
github.com/go-chi/chi/v5
github.com/go-chi/chi/v5/middleware
github.com/go-chi/cors

# WebSocket (live scan streaming)
github.com/gorilla/websocket

# Database
modernc.org/sqlite                      # pure-Go SQLite, no CGO
github.com/jackc/pgx/v5                 # PostgreSQL driver
github.com/golang-migrate/migrate/v4    # schema migrations

# Query generation (run sqlc to generate, not a runtime dep)
# dev tool: github.com/sqlc-dev/sqlc

# Concurrency
golang.org/x/sync                       # errgroup, semaphore

# Security tool libraries (embed as Go libs)
github.com/projectdiscovery/nuclei/v3/lib
github.com/projectdiscovery/httpx
github.com/projectdiscovery/subfinder/v2/pkg/runner
github.com/projectdiscovery/dnsx/libs/dnsx
github.com/projectdiscovery/naabu/v2/pkg/runner
github.com/Ullaakut/nmap/v3             # nmap Go wrapper

# LLM client (OpenAI-compatible — works with Ollama, LM Studio, llama.cpp)
github.com/sashabaranov/go-openai

# HTTP client (for CVE lookups, external API calls)
# stdlib net/http is sufficient

# Structured logging
log/slog                                # stdlib since Go 1.21

# Config file parsing
# viper handles YAML/TOML/JSON/env

# Report generation
github.com/jung-kurt/gofpdf             # PDF reports
html/template                           # stdlib, HTML reports

# Testing
github.com/stretchr/testify

# Build/release tooling (dev only)
# goreleaser for cross-platform release builds
```

### 3.3 Frontend — React + TypeScript

```
react 18
typescript 5
vite 5                      # build tool
react-router-dom v6         # routing within the SPA
@tanstack/react-query       # data fetching + caching
recharts                    # findings dashboard charts
cytoscape + cytoscape-cola  # attack graph visualization
shadcn/ui (copy-paste)      # component library (not a package dep)
@radix-ui/react-*           # shadcn peer deps
lucide-react                # icons
```

The frontend is built with `vite build` and the output `dist/` directory is embedded into the Go binary using `//go:embed web/dist`. The chi router serves it at `/` when `nox serve` is run.

### 3.4 Database

- **Default:** SQLite via `modernc.org/sqlite` (pure Go, no CGO, one `session.db` per session directory)
- **Optional:** PostgreSQL via `pgx/v5` for multi-user team deployments
- **Migration tool:** `golang-migrate` with numbered SQL files in `internal/db/migrations/`
- **Query layer:** `sqlc` — write `.sql` query files, generate type-safe Go code. Do NOT use an ORM.

### 3.5 Plugin System

Subprocess JSON-RPC. Each tool adapter is a standalone binary (any language). Nox spawns the binary, writes a JSON request to stdin, reads a JSON response from stdout. This is the initial plugin contract. The `hashicorp/go-plugin` (gRPC-based) system can replace this later for performance-critical adapters.

Tools from the ProjectDiscovery suite (nuclei, httpx, subfinder, naabu, dnsx) are embedded as Go libraries, not subprocess plugins.

### 3.6 Packaging

- **Docker:** Multi-stage build. Stage 1: build frontend (`node:20-alpine`). Stage 2: build Go binary (`golang:1.22-alpine`). Stage 3: final image (`kalilinux/kali-rolling` or `parrotsec/core`) with all external tool dependencies (nmap, sqlmap, dalfox, testssl.sh, ffuf, etc.) pre-installed.
- **Single binary option:** `goreleaser` for cross-platform binary releases. The binary embeds the frontend. External tools (nmap etc.) must be installed separately in this mode.

---

## 4. Project Structure

```
nox/
├── cmd/
│   ├── root.go              # cobra root command, global flags
│   ├── scan.go              # `nox scan` command
│   ├── serve.go             # `nox serve` — starts web UI + API
│   ├── report.go            # `nox report` — generate report from session
│   ├── sessions.go          # `nox sessions list/show/delete`
│   └── plugins.go           # `nox plugins list/install`
│
├── internal/
│   ├── engine/
│   │   ├── dag.go           # DAG runner: topological sort, phase execution
│   │   ├── scheduler.go     # concurrency control, rate limiting per tool
│   │   ├── session.go       # session lifecycle management
│   │   └── scope.go         # scope validation, in-scope checks
│   │
│   ├── adapters/            # one file per tool — implements the Adapter interface
│   │   ├── adapter.go       # Adapter interface definition
│   │   ├── nuclei.go
│   │   ├── nmap.go
│   │   ├── httpx.go
│   │   ├── subfinder.go
│   │   ├── dnsx.go
│   │   ├── naabu.go
│   │   ├── ffuf.go          # subprocess
│   │   ├── sqlmap.go        # subprocess
│   │   ├── dalfox.go        # subprocess
│   │   ├── ssrfmap.go       # subprocess
│   │   ├── testssl.go       # subprocess
│   │   ├── whatweb.go       # subprocess
│   │   ├── wpscan.go        # subprocess
│   │   ├── arjun.go         # subprocess
│   │   ├── gitleaks.go      # subprocess
│   │   ├── jwt_tool.go      # subprocess
│   │   └── subprocess.go    # generic subprocess JSON-RPC runner
│   │
│   ├── db/
│   │   ├── migrations/      # 001_initial.sql, 002_add_cve_matches.sql, ...
│   │   ├── queries/         # .sql files read by sqlc
│   │   ├── sqlc.yaml        # sqlc config
│   │   └── db.go            # DB connection init, migration runner
│   │   └── *.go             # sqlc-generated files (do not edit manually)
│   │
│   ├── models/
│   │   ├── finding.go       # Finding struct (the universal normalized type)
│   │   ├── session.go       # Session struct
│   │   ├── target.go        # Target struct
│   │   ├── cve.go           # CVEMatch struct
│   │   ├── attack_vector.go # AttackVector, AttackChain structs
│   │   └── report.go        # Report struct
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
│   ├── vectors/
│   │   ├── engine.go        # Attack vector engine: rule evaluation + LLM augmentation
│   │   ├── rules.go         # Rule definitions (if X + Y → attack chain Z)
│   │   └── scorer.go        # Confidence scoring for attack chains
│   │
│   ├── api/
│   │   ├── server.go        # chi router setup, middleware, embed.FS serving
│   │   ├── sessions.go      # /api/sessions endpoints
│   │   ├── scan.go          # /api/scan endpoints
│   │   ├── findings.go      # /api/findings endpoints
│   │   ├── vectors.go       # /api/vectors endpoints
│   │   ├── llm.go           # /api/llm endpoints (chat, analyse)
│   │   ├── reports.go       # /api/reports endpoints
│   │   └── ws.go            # WebSocket handler for live scan events
│   │
│   └── report/
│       ├── generator.go     # Report orchestration
│       ├── html.go          # HTML template rendering
│       ├── pdf.go           # PDF generation via gofpdf
│       └── templates/       # Go HTML templates
│
├── web/                     # React + TypeScript frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Sessions.tsx
│   │   │   ├── Findings.tsx
│   │   │   ├── AttackGraph.tsx
│   │   │   ├── LLMChat.tsx
│   │   │   └── Reports.tsx
│   │   ├── components/
│   │   ├── api/             # TanStack Query hooks + fetch wrappers
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── plugins/                 # External subprocess plugin specs + examples
│   ├── spec.md              # JSON-RPC contract documentation
│   └── example-python/     # Example Python plugin adapter
│
├── Dockerfile
├── docker-compose.yml
├── goreleaser.yaml
├── Makefile
└── README.md
```

---

## 5. Core Data Models (Go Structs)

These are the canonical Go types. The database schema is derived from these. sqlc generates query functions that map to/from these types.

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
    "nox/internal/models"
)

// Phase defines which scan phase this adapter runs in.
type Phase string

const (
    PhaseRecon          Phase = "recon"
    PhaseFingerprint    Phase = "fingerprint"
    PhaseEnumerate      Phase = "enumerate"
    PhaseVulnScan       Phase = "vuln_scan"
)

// AdapterInput is what Nox passes to every adapter.
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

Any process that speaks this JSON contract over stdin/stdout is a valid Nox plugin. The `internal/adapters/subprocess.go` file implements the generic subprocess runner.

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
| `linkfinder` | subprocess | Endpoints extracted from JavaScript files |
| `gitleaks` / `trufflehog` | subprocess | Secrets in JS files, git repos, public pages |
| CORS check | Go stdlib HTTP | Misconfigured CORS (allow-all origins, etc.) |
| S3/GCS enumeration | Go stdlib HTTP | Public cloud storage buckets |

**DependsOn:** all Phase 2 adapters (needs tech fingerprints and live hosts)

### Phase 4: Vulnerability Scanning
**Goal:** Confirm exploitable vulnerabilities. This phase is the most impactful and most dangerous — scope and rate limiting are critical here.

| Tool | Integration | What it finds |
|---|---|---|
| `nuclei` (vuln templates) | Go library | CVE-matched vulnerability templates |
| `sqlmap` | subprocess | SQL injection in discovered parameters |
| `dalfox` | subprocess | Reflected/stored/DOM XSS |
| `SSRFmap` | subprocess | SSRF in URL parameters and headers |
| `jwt_tool` | subprocess | JWT: alg:none, weak secret, key confusion |
| OAuth checks | Go stdlib HTTP | Open redirect in OAuth callbacks, CSRF |
| SSTI detection | Go stdlib HTTP | Server-side template injection |
| XXE fuzzing | Go stdlib HTTP | XML external entity injection |
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
            Description: "Request that Nox run an additional tool scan on a specific target or parameter",
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
You are Nox, an expert web application penetration testing assistant. You are analysing the results of automated security scans.

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

The chi router exposes these endpoints. All responses are JSON. Authentication is a local API key stored in the Nox config file (for when the web UI is accessible on a local network).

```
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

GET    /api/tools                   List all registered tool adapters
GET    /api/health                  Health check (DB connected, LLM reachable, tools available)

WS     /ws/scan/{id}               WebSocket — real-time scan events
```

### WebSocket Event Format

```json
{
  "type": "tool_started",   // tool_started | tool_completed | tool_error | finding_found | phase_completed | scan_completed
  "session_id": "uuid",
  "tool_id": "nuclei",
  "phase": "vuln_scan",
  "timestamp": "2025-01-15T14:23:01Z",
  "payload": {
    // type-specific data
    // for finding_found: the Finding object
    // for tool_completed: { duration_ms, finding_count }
    // for tool_error: { error_message }
  }
}
```

---

## 14. CLI Commands

```
nox scan --target <host/CIDR/URL>     Start a scan (most common command)
         --source /path/to/repo       Source-aware combined mode when target is present; static-only when target is absent
         --name "Engagement name"      Label for this session
         --mode passive|active|stealth Scan mode (default: active)
         --phases recon,fingerprint,...  Limit to specific phases
         --tools nuclei,sqlmap,...       Limit to specific tools
         --out-of-scope host1,host2     Exclude from scope
         --llm-model llama3:8b          LLM model to use
         --llm-url http://localhost:11434/v1
         --no-llm                       Skip LLM analysis
         --concurrency 5               Max concurrent tools (default: 3)
         --rate-limit 100              Max requests/second globally

nox audit <path>                      Run built-in static audit against source code
          --name "Audit name"         Label for this static session
          --format terminal|json|sarif|html|md
          --output audit.sarif        Output file (default: stdout for report formats)
          --fail-on critical|high|medium|low
          --diff path1,path2          Restrict audit findings to changed paths
          --tools audit/semgrep,...   Limit static adapters
          --offline                   Prefer offline-safe audit execution
          --no-llm                    Skip audit triage/dataflow/narrative LLM passes
nox audit findings <session-id>       List audit findings from a session
nox audit report <session-id>         Generate a report from an audit session
nox audit tools                       List built-in and external audit adapters

nox serve                             Start the web UI and API server
         --port 8080                  (default: 8080)
         --host 127.0.0.1            (default: localhost only)

nox sessions list                     List all sessions
nox sessions show <id>                Show session details
nox sessions delete <id>              Delete a session

nox report <session-id>               Generate report
          --format html|pdf|md|sarif  Output format (default: html)
          --output report.html        Output file (default: stdout)
          --mode executive|technical  Report depth (default: technical)

nox llm chat <session-id>             Interactive LLM chat about a session
nox llm analyse <session-id>          Run full LLM analysis and print results

nox plugins list                      List available adapters
nox plugins install <path>            Register a subprocess plugin binary

nox config init                       Create default config file (~/.nox/config.yaml)
nox config show                       Show current config
```

---

## 15. Web UI Pages

The frontend is a React SPA embedded in the Go binary. Routes:

### 15.1 Dashboard (`/`)
- Active and recent sessions list
- Quick-start new scan form (target input, mode selector, name)
- Global stats: total findings by severity across all sessions
- Combined-mode sessions show static and dynamic progress tracks through the
  same scan event stream.

### 15.2 Session Detail (`/sessions/:id`)
- Session metadata (target, mode, duration, status)
- Live scan progress: phase tracker, tool status indicators, real-time finding counter (via WebSocket)
- Findings table: sortable by severity/tool/type, filterable, paginated
- Severity distribution chart (Recharts donut)
- Tool coverage matrix (which tools ran, how many findings each produced)

### 15.3 Attack Graph (`/sessions/:id/graph`)
- Cytoscape.js force-directed graph
- Nodes: targets, technologies, findings, source findings, audit findings, attack vectors
- Edges: "discovered by", "exploits", "leads to", "affects", plus labelled source/audit graph edges (`enables`, `amplifies`, `requires`, `confirms`)
- Node colors: red = critical finding, orange = high, yellow = medium, blue = info, purple = attack vector/source
- Click any node to see full details in a side panel
- Filter by: severity, OWASP category, phase
- Highlight top graph-derived paths and static + dynamic confirmations.

### 15.4 Findings (`/sessions/:id/findings`)
- Full findings table with all fields
- Expandable rows showing raw evidence, HTTP request/response, CVE matches
- Bulk actions: export selected, change severity, add notes
- Filters: severity, type, tool, OWASP category, has CVE, has exploit
- Origin badges distinguish dynamic, static, and static + dynamic findings.
- Audit fields include status, notes, code context, and flow summary.

### 15.4a Source (`/sessions/:id/source`)
- Source finding table with context snippets, language/framework, kind, method,
  file path, line number, and risky-kind severity styling.
- Static + dynamic badges mark source findings confirmed by dynamic evidence.

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
  - Dismissed and suppressed audit findings
  - Cross-confirmed static/dynamic findings
  - Remediation roadmap (prioritised by severity)
  - Appendix: raw tool output

---

## 16. Configuration File

Default location: `~/.nox/config.yaml`

```yaml
# Nox configuration

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
  driver: sqlite            # sqlite | postgres
  path: ~/.nox/data/        # SQLite: directory where session directories are stored
  # PostgreSQL only:
  # host: localhost
  # port: 5432
  # name: nox
  # user: nox
  # password: ""

# Web server settings
server:
  host: 127.0.0.1
  port: 8080
  api_key: ""               # Empty = no auth (localhost only). Set for network access.

# Default scan settings
scan:
  default_mode: active
  default_concurrency: 3
  default_rate_limit: 100   # requests/second globally
  timeout_per_tool: 300     # seconds per tool run

# CVE intelligence
cve:
  enabled: true
  sources:
    - nvd
    - osv
    - circl
  nvd_api_key: ""           # Optional — higher rate limits with key
  cache_ttl: 86400          # seconds to cache CVE data

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
    - ~/.nox/plugins/
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
- **Integration tests** (opt-in, require Docker): spin up a vulnerable test target (e.g. DVWA, Juice Shop) and run a full scan, assert minimum finding counts.
- **API tests** use `net/http/httptest` to test all REST endpoints against an in-memory SQLite DB.

---

## 20. Docker Setup

```dockerfile
# Dockerfile

# Stage 1: Build frontend
FROM node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o nox ./cmd/nox

# Stage 3: Final image with all security tools
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    nmap nikto whatweb whois dnsutils curl \
    python3 python3-pip sqlmap \
    && pip3 install wpscan dalfox arjun trufflehog \
    && apt-get clean

COPY --from=builder /app/nox /usr/local/bin/nox

EXPOSE 8080
ENTRYPOINT ["nox"]
CMD ["serve"]
```

```yaml
# docker-compose.yml
services:
  nox:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - nox-data:/root/.nox/data
      - ./config.yaml:/root/.nox/config.yaml
    environment:
      - NOX_LLM_BASE_URL=http://ollama:11434/v1
      - NOX_LLM_MODEL=llama3:8b

  ollama:
    image: ollama/ollama
    volumes:
      - ollama-data:/root/.ollama
    ports:
      - "11434:11434"

volumes:
  nox-data:
  ollama-data:
```

---

## 21. Makefile

```makefile
.PHONY: build dev test lint web clean

build:
	cd web && npm run build
	go build -o bin/nox ./cmd/nox

dev:
	# Run Go API server and Vite dev server in parallel
	air &    # air is a Go hot-reload tool
	cd web && npm run dev

test:
	go test ./... -v

test-integration:
	docker compose -f docker-compose.test.yml up --abort-on-container-exit

lint:
	golangci-lint run
	cd web && npm run lint

web:
	cd web && npm run build

sqlc:
	sqlc generate

migrate-up:
	go run ./cmd/nox/main.go migrate up

clean:
	rm -rf bin/ web/dist/
```

---

## 22. Build Order Recommendation for AI Coding Assistant

Build in this order to have working, testable code at each step:

1. **Data models** (`internal/models/`) — all Go structs, no deps
2. **Database** (`internal/db/`) — migrations, sqlc schema, connection init
3. **Scope checker** (`internal/engine/scope.go`) — test independently
4. **Adapter interface + registry** (`internal/adapters/adapter.go`, `registry.go`)
5. **Subprocess runner** (`internal/adapters/subprocess.go`) — generic JSON-RPC runner
6. **First adapters** — start with `httpx`, `subfinder`, `nmap` (Go libraries)
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

> Nox is intended exclusively for authorized penetration testing, security research, and CTF challenges. Only use Nox against systems you own or have explicit, written permission to test. Unauthorized scanning or exploitation of systems is illegal in most jurisdictions. The authors accept no responsibility for misuse.

---

*End of Nox Project Specification — Version 1.0*
