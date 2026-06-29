import type { PagesCtx } from "../../../_lib/env";
import { badRequest, cachedJson, json, parseEventCursor, parseLimit, publicSha256, urlOf } from "../../../_lib/http";
import { redactPreview } from "../../../_lib/redaction";
import { publicEventPage, type EventRow } from "../../../_lib/rows";

interface PayloadRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  preview: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  max_confidence: number;
  unique_ips: number;
}

interface RelatedIpRow {
  source_ip: string;
  event_count: number;
  max_confidence: number;
  last_seen: string;
}

interface DimensionRow {
  key: string;
  count: number;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.sha256) ? ctx.params.sha256[0] : ctx.params.sha256;
  const sha256 = publicSha256(raw ?? null);
  if (!sha256) return badRequest("Invalid SHA-256 hash.");
  const url = urlOf(ctx.request);
  const limit = parseLimit(url, 100, 250);
  const cursor = parseEventCursor(url.searchParams.get("cursor"));
  if (cursor instanceof Response) return cursor;
  const eventWhere = ["payload_sha256 = ?"];
  const eventParams: unknown[] = [sha256];
  if (cursor) {
    eventWhere.push("(occurred_at < ? OR (occurred_at = ? AND id < ?))");
    eventParams.push(cursor.occurredAt, cursor.occurredAt, cursor.id);
  }
  eventParams.push(limit + 1);

  const payload = await ctx.env.DB.prepare(
    `SELECT p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count,
       COALESCE(MAX(e.confidence), 0) AS max_confidence,
       COUNT(DISTINCT e.source_ip) AS unique_ips
     FROM payloads p
     LEFT JOIN events e ON e.payload_sha256 = p.sha256
     WHERE p.sha256 = ?
     GROUP BY p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count`
  ).bind(sha256).first<PayloadRow>();
  if (!payload) return json({ error: "not_found" }, { status: 404 });

  const [relatedIps, protocols, traps, events] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT source_ip, COUNT(*) AS event_count, MAX(confidence) AS max_confidence, MAX(occurred_at) AS last_seen
       FROM events
       WHERE payload_sha256 = ?
       GROUP BY source_ip
       ORDER BY event_count DESC, last_seen DESC
       LIMIT 100`
    ).bind(sha256).all<RelatedIpRow>(),
    ctx.env.DB.prepare(
      `SELECT protocol AS key, COUNT(*) AS count
       FROM events
       WHERE payload_sha256 = ?
       GROUP BY protocol
       ORDER BY count DESC
       LIMIT 25`
    ).bind(sha256).all<DimensionRow>(),
    ctx.env.DB.prepare(
      `SELECT trap AS key, COUNT(*) AS count
       FROM events
       WHERE payload_sha256 = ?
       GROUP BY trap
       ORDER BY count DESC
       LIMIT 25`
    ).bind(sha256).all<DimensionRow>(),
    ctx.env.DB.prepare(
      `SELECT id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
        http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
       payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate,
       pcap_sha256, pcap_available, severity, confidence, confidence_reasons_json, tags_json
       FROM events
       WHERE ${eventWhere.join(" AND ")}
       ORDER BY occurred_at DESC, id DESC
       LIMIT ?`
    ).bind(...eventParams).all<EventRow>()
  ]);
  const eventPage = publicEventPage(events.results, limit);

  return cachedJson({
    payload: {
      ...payload,
      preview: redactPreview(payload.preview)
    },
    related_ips: relatedIps.results,
    protocols: protocols.results,
    traps: traps.results,
    ...eventPage
  });
};
