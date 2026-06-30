CREATE TABLE IF NOT EXISTS hunt_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  min_confidence INTEGER NOT NULL DEFAULT 50,
  trap TEXT,
  protocol TEXT,
  tag TEXT,
  has_credentials INTEGER,
  cursor_occurred_at TEXT,
  cursor_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id TEXT PRIMARY KEY,
  hunt_rule_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_delivered_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (hunt_rule_id) REFERENCES hunt_rules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hunt_rules_enabled ON hunt_rules (enabled);
