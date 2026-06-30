import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, feedLimitParam, parseSinceIso, urlOf } from "../../../_lib/http";
import { publicIpIoc, type IpProfileRow } from "../../../_lib/ipIocs";
import { publicEvent, type EventRow } from "../../../_lib/rows";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const since = parseSinceIso(url.searchParams.get("since"));
  if (since instanceof Response) return since;

  const rawMinConfidence = url.searchParams.get("minConfidence");
  const minConfidence = rawMinConfidence === null ? 50 : Number(rawMinConfidence);
  if (!Number.isInteger(minConfidence) || minConfidence < 0 || minConfidence > 100) {
    return new Response("invalid minConfidence", { status: 400 });
  }

  const limit = feedLimitParam(url, 500);

  const [ipResult, eventResult] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT source_ip, first_seen, last_seen, score, confidence, confidence_reasons_json,
         unique_traps_json, protocols_json
       FROM ip_profiles
       WHERE first_seen >= ? AND confidence >= ?
       ORDER BY first_seen DESC, confidence DESC
       LIMIT ?`
    )
      .bind(since, minConfidence, limit)
      .all<IpProfileRow>(),
    ctx.env.DB.prepare(
      `SELECT id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
        http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
        payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate,
        pcap_sha256, pcap_available, severity, confidence, confidence_reasons_json, tags_json
       FROM events
       WHERE occurred_at >= ? AND confidence >= ?
       ORDER BY occurred_at DESC, id DESC
       LIMIT ?`
    )
      .bind(since, minConfidence, limit)
      .all<EventRow>()
  ]);

  return cachedJson({
    since,
    min_confidence: minConfidence,
    ips: ipResult.results.map(publicIpIoc),
    events: eventResult.results.map(publicEvent)
  });
};
