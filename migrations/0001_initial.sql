CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  source_port INTEGER,
  destination_port INTEGER,
  protocol TEXT NOT NULL,
  trap TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  http_method TEXT,
  http_path TEXT,
  http_status INTEGER,
  user_agent TEXT,
  credential_kind TEXT,
  has_username INTEGER NOT NULL DEFAULT 0,
  has_password INTEGER NOT NULL DEFAULT 0,
  payload_sha256 TEXT,
  payload_size INTEGER NOT NULL DEFAULT 0,
  payload_preview TEXT NOT NULL DEFAULT '',
  severity INTEGER NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  r2_key TEXT NOT NULL,
  indexed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip_time ON events (source_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_protocol_time ON events (protocol, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_trap_time ON events (trap, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_time ON events (severity DESC, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_payload_sha256 ON events (payload_sha256);

CREATE TABLE IF NOT EXISTS ip_profiles (
  source_ip TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0,
  score INTEGER NOT NULL DEFAULT 0,
  unique_traps_json TEXT NOT NULL DEFAULT '[]',
  protocols_json TEXT NOT NULL DEFAULT '[]',
  last_trap TEXT,
  last_protocol TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_profiles_score ON ip_profiles (score DESC, event_count DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ip_profiles_last_seen ON ip_profiles (last_seen DESC);

CREATE TABLE IF NOT EXISTS sensor_health (
  sensor_id TEXT PRIMARY KEY,
  last_seen TEXT NOT NULL,
  last_protocol TEXT,
  last_trap TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payloads (
  sha256 TEXT PRIMARY KEY,
  size_bytes INTEGER NOT NULL,
  mime_guess TEXT NOT NULL,
  preview TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS analytics_rollups (
  bucket_start TEXT NOT NULL,
  bucket_width TEXT NOT NULL CHECK (bucket_width IN ('hour', 'day')),
  dimension TEXT NOT NULL,
  key TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  unique_ips INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (bucket_start, bucket_width, dimension, key)
);

CREATE TABLE IF NOT EXISTS rollup_unique_ips (
  bucket_start TEXT NOT NULL,
  bucket_width TEXT NOT NULL CHECK (bucket_width IN ('hour', 'day')),
  dimension TEXT NOT NULL,
  key TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  PRIMARY KEY (bucket_start, bucket_width, dimension, key, source_ip)
);
