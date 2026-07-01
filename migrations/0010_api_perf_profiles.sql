CREATE INDEX IF NOT EXISTS idx_ip_profiles_window_rank
  ON ip_profiles (last_seen DESC, event_count DESC, confidence DESC);
