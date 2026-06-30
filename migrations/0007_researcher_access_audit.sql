CREATE TABLE IF NOT EXISTS researcher_access_log (
  id TEXT PRIMARY KEY,
  accessed_at TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  client_ip TEXT,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_researcher_access_log_at ON researcher_access_log (accessed_at DESC);
