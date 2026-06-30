CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_hunt_rule ON webhook_subscriptions (hunt_rule_id, enabled);
