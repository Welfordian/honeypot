ALTER TABLE events ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN confidence_reasons_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE ip_profiles ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ip_profiles ADD COLUMN confidence_reasons_json TEXT NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_events_confidence_time ON events (confidence DESC, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_profiles_confidence ON ip_profiles (confidence DESC, event_count DESC, last_seen DESC);
