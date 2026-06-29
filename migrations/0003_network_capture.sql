ALTER TABLE events ADD COLUMN event_kind TEXT NOT NULL DEFAULT 'trap';
ALTER TABLE events ADD COLUMN packet_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN byte_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN tcp_flags TEXT;
ALTER TABLE events ADD COLUMN is_aggregate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN pcap_sha256 TEXT;
ALTER TABLE events ADD COLUMN pcap_available INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_events_kind_time ON events (event_kind, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_destination_port_time ON events (destination_port, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_tcp_flags_time ON events (tcp_flags, occurred_at DESC);

CREATE TABLE IF NOT EXISTS pcap_chunks (
  capture_id TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  interface_name TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL,
  packet_count INTEGER NOT NULL DEFAULT 0,
  source_ips_json TEXT NOT NULL DEFAULT '[]',
  r2_key TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  uploaded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pcap_chunks_uploaded_at ON pcap_chunks (uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcap_chunks_expires_at ON pcap_chunks (expires_at);
CREATE INDEX IF NOT EXISTS idx_pcap_chunks_sha256 ON pcap_chunks (sha256);
