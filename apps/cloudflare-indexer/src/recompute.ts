import type { Env } from "./types.js";
import { confidenceForEvent, confidenceForProfile } from "@honeypot/shared";

interface RecomputeRequest {
  limit?: unknown;
  afterId?: unknown;
}

interface EventConfidenceRow {
  id: string;
  source_ip: string;
  severity: number;
  protocol: string;
  trap: string;
  http_path: string | null;
  user_agent: string | null;
  has_username: number;
  has_password: number;
  payload_sha256: string | null;
  payload_size: number;
}

interface ProfileConfidenceRow {
  event_count: number;
  unique_traps_json: string;
  protocols_json: string;
}

interface TopConfidenceRow {
  confidence: number;
  confidence_reasons_json: string;
}

function parseList(value: string | null): string[] {
  try {
    const parsed = JSON.parse(value ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function parseLimit(value: unknown): number {
  const parsed = typeof value === "number" ? value : Number(value ?? 1000);
  if (!Number.isFinite(parsed)) return 1000;
  return Math.max(1, Math.min(5000, Math.trunc(parsed)));
}

function parseAfterId(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9-]{1,120}$/.test(value) ? value : "";
}

async function recomputeProfile(env: Env, sourceIp: string): Promise<boolean> {
  const profile = await env.DB.prepare(
    "SELECT event_count, unique_traps_json, protocols_json FROM ip_profiles WHERE source_ip = ?"
  ).bind(sourceIp).first<ProfileConfidenceRow>();
  if (!profile) return false;

  const top = await env.DB.prepare(
    `SELECT confidence, confidence_reasons_json
     FROM events
     WHERE source_ip = ?
     ORDER BY confidence DESC, occurred_at DESC
     LIMIT 1`
  ).bind(sourceIp).first<TopConfidenceRow>();

  const confidence = confidenceForProfile({
    maxEventConfidence: top?.confidence ?? 0,
    eventCount: profile.event_count,
    uniqueTraps: parseList(profile.unique_traps_json),
    protocols: parseList(profile.protocols_json),
    eventReasons: parseList(top?.confidence_reasons_json ?? null)
  });

  await env.DB.prepare(
    `UPDATE ip_profiles
     SET confidence = ?, confidence_reasons_json = ?, updated_at = ?
     WHERE source_ip = ?`
  ).bind(confidence.confidence, JSON.stringify(confidence.reasons), new Date().toISOString(), sourceIp).run();
  return true;
}

export async function recomputeConfidence(env: Env, body: RecomputeRequest): Promise<Record<string, unknown>> {
  const limit = parseLimit(body.limit);
  const afterId = parseAfterId(body.afterId);

  const rows = await env.DB.prepare(
    `SELECT id, source_ip, severity, protocol, trap, http_path, user_agent, has_username, has_password, payload_sha256, payload_size
     FROM events
     WHERE id > ?
     ORDER BY id
     LIMIT ?`
  ).bind(afterId, limit).all<EventConfidenceRow>();

  const affectedIps = new Set<string>();
  let nextCursor = afterId;

  for (const row of rows.results) {
    const confidence = confidenceForEvent({
      severity: row.severity,
      protocol: row.protocol,
      trap: row.trap,
      httpPath: row.http_path,
      userAgent: row.user_agent,
      hasCredentials: Boolean(row.has_username || row.has_password),
      hasPayload: Boolean(row.payload_sha256 || row.payload_size > 0)
    });

    await env.DB.prepare(
      `UPDATE events
       SET confidence = ?, confidence_reasons_json = ?
       WHERE id = ?`
    ).bind(confidence.confidence, JSON.stringify(confidence.reasons), row.id).run();

    affectedIps.add(row.source_ip);
    nextCursor = row.id;
  }

  let updatedProfiles = 0;
  for (const ip of affectedIps) {
    if (await recomputeProfile(env, ip)) updatedProfiles += 1;
  }

  return {
    updated_events: rows.results.length,
    updated_profiles: updatedProfiles,
    next_cursor: nextCursor || null,
    done: rows.results.length < limit
  };
}
