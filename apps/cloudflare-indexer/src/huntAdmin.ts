import type { Env } from "./types.js";
import { validateWebhookUrl } from "../../../functions/_lib/webhookUrl.js";

interface HuntRuleRow {
  id: string;
  name: string;
  enabled: number;
  min_confidence: number;
  trap: string | null;
  protocol: string | null;
  tag: string | null;
  has_credentials: number | null;
  cursor_occurred_at: string | null;
  cursor_id: string | null;
  created_at: string;
  updated_at: string;
}

interface WebhookRow {
  id: string;
  hunt_rule_id: string;
  url: string;
  enabled: number;
  last_delivered_at: string | null;
  last_error: string | null;
  created_at: string;
}

function json(body: unknown, init?: ResponseInit): Response {
  return Response.json(body, init);
}

function publicHuntRule(row: HuntRuleRow) {
  return {
    id: row.id,
    name: row.name,
    enabled: Boolean(row.enabled),
    min_confidence: row.min_confidence,
    trap: row.trap,
    protocol: row.protocol,
    tag: row.tag,
    has_credentials: row.has_credentials === null ? null : Boolean(row.has_credentials),
    cursor_occurred_at: row.cursor_occurred_at,
    cursor_id: row.cursor_id,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function publicWebhook(row: WebhookRow) {
  return {
    id: row.id,
    hunt_rule_id: row.hunt_rule_id,
    url: row.url,
    enabled: Boolean(row.enabled),
    last_delivered_at: row.last_delivered_at,
    last_error: row.last_error,
    created_at: row.created_at
  };
}

function parseOptionalBoolean(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value === 1 || value === 0) return value;
  return null;
}

function parseToken(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return null;
  return /^[A-Za-z0-9_.-]+$/.test(trimmed) ? trimmed : null;
}

export async function handleHuntRulesAdmin(request: Request, env: Env): Promise<Response> {
  if (request.method === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM hunt_rules ORDER BY created_at DESC").all<HuntRuleRow>();
    return json({ hunt_rules: rows.results.map(publicHuntRule) });
  }

  if (request.method === "POST") {
    const body = (await request.json()) as Record<string, unknown>;
    const now = new Date().toISOString();
    const id = typeof body.id === "string" && body.id.trim() ? body.id.trim() : crypto.randomUUID();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > 120) return json({ error: "invalid_name" }, { status: 400 });

    const minConfidence = Number(body.min_confidence ?? 50);
    if (!Number.isInteger(minConfidence) || minConfidence < 0 || minConfidence > 100) {
      return json({ error: "invalid_min_confidence" }, { status: 400 });
    }

    const enabled = body.enabled === false ? 0 : 1;
    const trap = body.trap === null || body.trap === undefined ? null : parseToken(body.trap, 120);
    const protocol = body.protocol === null || body.protocol === undefined ? null : parseToken(body.protocol, 24);
    const tag = body.tag === null || body.tag === undefined ? null : parseToken(body.tag, 80);
    if (body.trap && !trap) return json({ error: "invalid_trap" }, { status: 400 });
    if (body.protocol && !protocol) return json({ error: "invalid_protocol" }, { status: 400 });
    if (body.tag && !tag) return json({ error: "invalid_tag" }, { status: 400 });

    const hasCredentials = parseOptionalBoolean(body.has_credentials);
    if (body.has_credentials !== null && body.has_credentials !== undefined && hasCredentials === null) {
      return json({ error: "invalid_has_credentials" }, { status: 400 });
    }

    const existing = await env.DB.prepare("SELECT id FROM hunt_rules WHERE id = ?").bind(id).first();
    if (existing) {
      await env.DB.prepare(
        `UPDATE hunt_rules SET
          name = ?, enabled = ?, min_confidence = ?, trap = ?, protocol = ?, tag = ?, has_credentials = ?, updated_at = ?
         WHERE id = ?`
      )
        .bind(name, enabled, minConfidence, trap, protocol, tag, hasCredentials, now, id)
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO hunt_rules (
          id, name, enabled, min_confidence, trap, protocol, tag, has_credentials, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(id, name, enabled, minConfidence, trap, protocol, tag, hasCredentials, now, now)
        .run();
    }

    const row = await env.DB.prepare("SELECT * FROM hunt_rules WHERE id = ?").bind(id).first<HuntRuleRow>();
    return json({ hunt_rule: row ? publicHuntRule(row) : null });
  }

  return json({ error: "method_not_allowed" }, { status: 405 });
}

export async function handleWebhookSubscriptionsAdmin(request: Request, env: Env): Promise<Response> {
  if (request.method === "GET") {
    const url = new URL(request.url);
    const huntRuleId = url.searchParams.get("hunt_rule_id");
    const rows = huntRuleId
      ? await env.DB.prepare("SELECT * FROM webhook_subscriptions WHERE hunt_rule_id = ? ORDER BY created_at DESC")
          .bind(huntRuleId)
          .all<WebhookRow>()
      : await env.DB.prepare("SELECT * FROM webhook_subscriptions ORDER BY created_at DESC").all<WebhookRow>();
    return json({ webhook_subscriptions: rows.results.map(publicWebhook) });
  }

  if (request.method === "POST") {
    const body = (await request.json()) as Record<string, unknown>;
    const now = new Date().toISOString();
    const id = typeof body.id === "string" && body.id.trim() ? body.id.trim() : crypto.randomUUID();
    const huntRuleId = typeof body.hunt_rule_id === "string" ? body.hunt_rule_id.trim() : "";
    const webhookUrl = typeof body.url === "string" ? body.url.trim() : "";
    if (!huntRuleId) return json({ error: "missing_hunt_rule_id" }, { status: 400 });
    if (!webhookUrl || webhookUrl.length > 2048) return json({ error: "invalid_url" }, { status: 400 });

    const parsedUrl = validateWebhookUrl(webhookUrl);
    if (parsedUrl instanceof Response) return parsedUrl;

    const hunt = await env.DB.prepare("SELECT id FROM hunt_rules WHERE id = ?").bind(huntRuleId).first();
    if (!hunt) return json({ error: "hunt_rule_not_found" }, { status: 404 });

    const enabled = body.enabled === false ? 0 : 1;
    const secret = typeof body.secret === "string" && body.secret.trim() ? body.secret.trim().slice(0, 256) : null;
    const existing = await env.DB.prepare("SELECT id FROM webhook_subscriptions WHERE id = ?").bind(id).first();

    if (existing) {
      await env.DB.prepare(
        `UPDATE webhook_subscriptions SET hunt_rule_id = ?, url = ?, secret = ?, enabled = ? WHERE id = ?`
      )
        .bind(huntRuleId, webhookUrl, secret, enabled, id)
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO webhook_subscriptions (id, hunt_rule_id, url, secret, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(id, huntRuleId, webhookUrl, secret, enabled, now)
        .run();
    }

    const row = await env.DB.prepare("SELECT * FROM webhook_subscriptions WHERE id = ?").bind(id).first<WebhookRow>();
    return json({ webhook_subscription: row ? publicWebhook(row) : null });
  }

  if (request.method === "DELETE") {
    const url = new URL(request.url);
    const id = url.searchParams.get("id");
    if (!id) return json({ error: "missing_id" }, { status: 400 });
    await env.DB.prepare("DELETE FROM webhook_subscriptions WHERE id = ?").bind(id).run();
    return json({ deleted: true, id });
  }

  return json({ error: "method_not_allowed" }, { status: 405 });
}
