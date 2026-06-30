import type { Env } from "./types.js";
import { eventMatchesHunt } from "../../../functions/_lib/huntMatch.js";
import { redactPreview } from "../../../functions/_lib/redaction.js";
import { postWebhook as deliverWebhook } from "../../../functions/_lib/webhookUrl.js";

interface HuntRuleRow {
  id: string;
  name: string;
  min_confidence: number;
  trap: string | null;
  protocol: string | null;
  tag: string | null;
  has_credentials: number | null;
  cursor_occurred_at: string | null;
  cursor_id: string | null;
}

interface WebhookRow {
  id: string;
  url: string;
  secret: string | null;
}

interface EventRow {
  id: string;
  occurred_at: string;
  source_ip: string;
  protocol: string;
  trap: string;
  confidence: number;
  has_username: number;
  has_password: number;
  tags_json: string;
  event_kind: string;
  http_method: string | null;
  http_path: string | null;
  payload_preview: string;
}

const BATCH_LIMIT = 100;

export function eventSummary(event: EventRow): string {
  const parts = [`${event.protocol}/${event.trap}`, `from ${event.source_ip}`, `confidence ${event.confidence}`];
  if (event.http_method && event.http_path) parts.push(`${event.http_method} ${event.http_path}`);
  else if (event.payload_preview) parts.push(redactPreview(event.payload_preview).slice(0, 120));
  return parts.join(" · ");
}

async function signBody(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function postWebhook(
  webhook: WebhookRow,
  rule: HuntRuleRow,
  event: EventRow
): Promise<void> {
  const payload = {
    hunt_rule_id: rule.id,
    hunt_name: rule.name,
    event: {
      id: event.id,
      occurred_at: event.occurred_at,
      source_ip: event.source_ip,
      protocol: event.protocol,
      trap: event.trap,
      event_kind: event.event_kind,
      confidence: event.confidence,
      summary: eventSummary(event)
    }
  };
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "user-agent": "honeypot-hunt-webhook/1"
  };
  if (webhook.secret) {
    headers["x-honeypot-signature"] = `sha256=${await signBody(webhook.secret, body)}`;
  }

  await deliverWebhook(webhook.url, { headers, body });
}

async function queryEventsSinceCursor(db: Env["DB"], rule: HuntRuleRow): Promise<EventRow[]> {
  const cursorAt = rule.cursor_occurred_at ?? "1970-01-01T00:00:00.000Z";
  const cursorId = rule.cursor_id ?? "";

  const rows = await db
    .prepare(
      `SELECT id, occurred_at, source_ip, protocol, trap, confidence, has_username, has_password, tags_json,
              event_kind, http_method, http_path, payload_preview
       FROM events
       WHERE occurred_at > ? OR (occurred_at = ? AND id > ?)
       ORDER BY occurred_at ASC, id ASC
       LIMIT ?`
    )
    .bind(cursorAt, cursorAt, cursorId, BATCH_LIMIT)
    .all<EventRow>();

  return rows.results;
}

async function deliverForRule(
  db: Env["DB"],
  rule: HuntRuleRow
): Promise<{ delivered: number; errors: number }> {
  const webhooks = await db
    .prepare("SELECT id, url, secret FROM webhook_subscriptions WHERE hunt_rule_id = ? AND enabled = 1")
    .bind(rule.id)
    .all<WebhookRow>();

  if (!webhooks.results.length) return { delivered: 0, errors: 0 };

  const events = await queryEventsSinceCursor(db, rule);
  let delivered = 0;
  let errors = 0;
  const cursorAt = rule.cursor_occurred_at ?? "";
  const cursorId = rule.cursor_id ?? "";
  let lastDeliveredOccurredAt: string | null = null;
  let lastDeliveredId: string | null = null;

  for (const event of events) {
    if (!eventMatchesHunt(event, rule)) {
      lastDeliveredOccurredAt = event.occurred_at;
      lastDeliveredId = event.id;
      continue;
    }

    let eventDelivered = true;
    for (const webhook of webhooks.results) {
      const now = new Date().toISOString();
      try {
        await postWebhook(webhook, rule, event);
        await db
          .prepare("UPDATE webhook_subscriptions SET last_delivered_at = ?, last_error = NULL WHERE id = ?")
          .bind(now, webhook.id)
          .run();
        delivered += 1;
      } catch (error) {
        eventDelivered = false;
        errors += 1;
        const message = error instanceof Error ? error.message : String(error);
        await db
          .prepare("UPDATE webhook_subscriptions SET last_error = ? WHERE id = ?")
          .bind(message.slice(0, 500), webhook.id)
          .run();
        console.error("hunt webhook delivery failed", rule.id, webhook.id, message);
      }
    }

    if (!eventDelivered) break;

    lastDeliveredOccurredAt = event.occurred_at;
    lastDeliveredId = event.id;
  }

  if (
    lastDeliveredOccurredAt &&
    lastDeliveredId &&
    (lastDeliveredOccurredAt !== cursorAt || lastDeliveredId !== cursorId)
  ) {
    await db
      .prepare("UPDATE hunt_rules SET cursor_occurred_at = ?, cursor_id = ?, updated_at = ? WHERE id = ?")
      .bind(lastDeliveredOccurredAt, lastDeliveredId, new Date().toISOString(), rule.id)
      .run();
  }

  return { delivered, errors };
}

export async function deliverHuntWebhooks(env: Env): Promise<{ rules: number; delivered: number; errors: number }> {
  const rules = await env.DB.prepare("SELECT * FROM hunt_rules WHERE enabled = 1").all<HuntRuleRow>();

  let delivered = 0;
  let errors = 0;

  for (const rule of rules.results) {
    const result = await deliverForRule(env.DB, rule);
    delivered += result.delivered;
    errors += result.errors;
  }

  return { rules: rules.results.length, delivered, errors };
}
