CREATE TABLE IF NOT EXISTS ingest_watermark (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_event_at TEXT,
  last_received_at TEXT,
  updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO ingest_watermark (id, last_event_at, last_received_at, updated_at)
SELECT 1, MAX(occurred_at), MAX(received_at), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM events;

CREATE INDEX IF NOT EXISTS idx_analytics_rollups_window
  ON analytics_rollups (bucket_width, dimension, bucket_start);

CREATE INDEX IF NOT EXISTS idx_rollup_unique_ips_window
  ON rollup_unique_ips (bucket_width, bucket_start);

CREATE INDEX IF NOT EXISTS idx_events_occurred_source
  ON events (occurred_at, source_ip);

CREATE INDEX IF NOT EXISTS idx_events_occurred_payload
  ON events (occurred_at, payload_sha256)
  WHERE payload_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_occurred_high_confidence
  ON events (occurred_at, source_ip)
  WHERE confidence >= 80;

CREATE INDEX IF NOT EXISTS idx_events_occurred_credentials
  ON events (occurred_at)
  WHERE has_username = 1 OR has_password = 1;
