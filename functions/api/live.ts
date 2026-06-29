import type { PagesCtx } from "../_lib/env";
import { json, urlOf, parseLimit } from "../_lib/http";
import { publicEvent, type EventRow } from "../_lib/rows";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const limit = parseLimit(url, 100, 200);
  const result = await ctx.env.DB.prepare(
    `SELECT id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
      http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
      payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate,
      pcap_sha256, pcap_available, severity, confidence, confidence_reasons_json, tags_json
     FROM events
     ORDER BY occurred_at DESC
     LIMIT ?`
  ).bind(limit).all<EventRow>();
  return json({ events: result.results.map(publicEvent), polled_at: new Date().toISOString() });
};
