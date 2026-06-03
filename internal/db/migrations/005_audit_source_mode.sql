ALTER TABLE sessions ADD COLUMN workload_mode TEXT NOT NULL DEFAULT 'dynamic';
ALTER TABLE sessions ADD COLUMN source_path TEXT NOT NULL DEFAULT '';

CREATE TABLE findings_new (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_id            TEXT REFERENCES targets(id) ON DELETE CASCADE,
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
    code_context         TEXT NOT NULL DEFAULT '',
    flow_summary         TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'open',
    notes                TEXT NOT NULL DEFAULT '',
    tags                 TEXT NOT NULL DEFAULT '[]',
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO findings_new (
    id, session_id, target_id, tool_id, type, severity, confidence, cvss_score,
    title, description, remediation, url, parameter, method, evidence_raw,
    evidence_normalized, tags, created_at
)
SELECT
    id, session_id, target_id, tool_id, type, severity, confidence, cvss_score,
    title, description, remediation, url, parameter, method, evidence_raw,
    evidence_normalized, tags, created_at
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
CREATE INDEX idx_findings_session ON findings(session_id);
CREATE INDEX idx_findings_target ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);

ALTER TABLE cve_matches ADD COLUMN package_name TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_matches ADD COLUMN package_version TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_matches ADD COLUMN session_id TEXT NOT NULL DEFAULT '';

CREATE TABLE source_findings (
    id                   TEXT PRIMARY KEY,
    session_id           TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind                 TEXT NOT NULL,
    language             TEXT NOT NULL,
    framework            TEXT NOT NULL,
    file_path            TEXT NOT NULL,
    line_number          INTEGER NOT NULL DEFAULT 0,
    value                TEXT NOT NULL DEFAULT '',
    method               TEXT NOT NULL DEFAULT '',
    context              TEXT NOT NULL DEFAULT '',
    notes                TEXT NOT NULL DEFAULT '',
    confirmed_by_dynamic BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_source_findings_session ON source_findings(session_id);
CREATE INDEX idx_source_findings_kind ON source_findings(kind);

CREATE TABLE attack_graph_edges (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    from_id     TEXT NOT NULL,
    to_id       TEXT NOT NULL,
    relation    TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_attack_graph_edges_session ON attack_graph_edges(session_id);
