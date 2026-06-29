import type { PagesCtx } from "../../../_lib/env";
import { badRequest, cachedJson, json, parseEventCursor, parseLimit, publicIp, urlOf } from "../../../_lib/http";
import { parseJsonList, publicEventPage, type EventRow } from "../../../_lib/rows";

interface IpRow {
  source_ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  score: number;
  confidence: number;
  confidence_reasons_json: string;
  unique_traps_json: string;
  protocols_json: string;
  last_trap: string | null;
  last_protocol: string | null;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.ip) ? ctx.params.ip[0] : ctx.params.ip;
  const ip = publicIp(raw ?? null);
  if (!ip) return badRequest("Invalid IP address.");
  const url = urlOf(ctx.request);
  const limit = parseLimit(url, 100, 250);
  const cursor = parseEventCursor(url.searchParams.get("cursor"));
  if (cursor instanceof Response) return cursor;
  const eventWhere = ["source_ip = ?"];
  const eventParams: unknown[] = [ip];
  if (cursor) {
    eventWhere.push("(occurred_at < ? OR (occurred_at = ? AND id < ?))");
    eventParams.push(cursor.occurredAt, cursor.occurredAt, cursor.id);
  }
  eventParams.push(limit + 1);

  const profile = await ctx.env.DB.prepare(
    `SELECT source_ip, first_seen, last_seen, event_count, score, confidence, confidence_reasons_json,
       unique_traps_json, protocols_json, last_trap, last_protocol
     FROM ip_profiles WHERE source_ip = ?`
  ).bind(ip).first<IpRow>();
  if (!profile) return json({ error: "not_found" }, { status: 404 });

  const events = await ctx.env.DB.prepare(
    `SELECT id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
      http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
      payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate,
      pcap_sha256, pcap_available, severity, confidence, confidence_reasons_json, tags_json
     FROM events
     WHERE ${eventWhere.join(" AND ")}
     ORDER BY occurred_at DESC, id DESC
     LIMIT ?`
  ).bind(...eventParams).all<EventRow>();
  const eventPage = publicEventPage(events.results, limit);

  return cachedJson({
    profile: {
      source_ip: profile.source_ip,
      first_seen: profile.first_seen,
      last_seen: profile.last_seen,
      event_count: profile.event_count,
      score: profile.score,
      confidence: profile.confidence,
      confidence_reasons: parseJsonList(profile.confidence_reasons_json),
      unique_traps: parseJsonList(profile.unique_traps_json),
      protocols: parseJsonList(profile.protocols_json),
      last_trap: profile.last_trap,
      last_protocol: profile.last_protocol
    },
    ...eventPage
  });
};
