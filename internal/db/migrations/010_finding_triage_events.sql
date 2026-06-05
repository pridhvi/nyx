CREATE TABLE IF NOT EXISTS finding_triage_events (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  field TEXT NOT NULL,
  old_value TEXT NOT NULL DEFAULT '',
  new_value TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'operator',
  created_at DATETIME NOT NULL,
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_triage_events_finding
  ON finding_triage_events(finding_id, created_at);
