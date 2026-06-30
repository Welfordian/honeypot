CREATE TABLE IF NOT EXISTS ip_reputation_cache (
  source_ip TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  classification TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  raw_json TEXT,
  fetched_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_expires ON ip_reputation_cache (expires_at);
