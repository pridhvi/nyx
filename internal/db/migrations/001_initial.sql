CREATE TABLE sessions (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'pending',
    mode           TEXT NOT NULL DEFAULT 'active',
    target_input   TEXT NOT NULL,
    in_scope       TEXT NOT NULL DEFAULT '[]',
    out_of_scope   TEXT NOT NULL DEFAULT '[]',
    enabled_phases TEXT NOT NULL DEFAULT '[]',
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
    evidence_normalized  TEXT NOT NULL DEFAULT '',
    tags                 TEXT NOT NULL DEFAULT '[]',
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_findings_session ON findings(session_id);
CREATE INDEX idx_findings_target ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE http_evidence (
    id             TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    request_raw    TEXT NOT NULL DEFAULT '',
    response_raw   TEXT NOT NULL DEFAULT '',
    status_code    INTEGER NOT NULL DEFAULT 0,
    response_time  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE cve_matches (
    id                TEXT PRIMARY KEY,
    finding_id        TEXT REFERENCES findings(id) ON DELETE CASCADE,
    technology_id     TEXT REFERENCES technologies(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    cvss_v3_score     REAL NOT NULL DEFAULT 0.0,
    cvss_v3_vector    TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    patch_available   BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    "references"      TEXT NOT NULL DEFAULT '[]',
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
    steps               TEXT NOT NULL DEFAULT '[]',
    prereq_finding_ids  TEXT NOT NULL DEFAULT '[]',
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
    args           TEXT NOT NULL DEFAULT '[]',
    stdout_raw     TEXT NOT NULL DEFAULT '',
    stderr_raw     TEXT NOT NULL DEFAULT '',
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
    messages        TEXT NOT NULL DEFAULT '[]',
    total_tokens    INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_llm_session ON llm_analyses(session_id);
