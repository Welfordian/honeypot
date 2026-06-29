import type { PagesCtx } from "../../_lib/env";
import { json, parseLimit, urlOf } from "../../_lib/http";
import { parseJsonList } from "../../_lib/rows";

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
  const limit = parseLimit(urlOf(ctx.request), 100, 500);
  const result = await ctx.env.DB.prepare(
    `SELECT source_ip, first_seen, last_seen, event_count, score, confidence, confidence_reasons_json, unique_traps_json, protocols_json, last_trap, last_protocol
     FROM ip_profiles
     ORDER BY confidence DESC, score DESC, event_count DESC, last_seen DESC
     LIMIT ?`
  ).bind(limit).all<IpRow>();
  return json({
    ips: result.results.map((row) => ({
      source_ip: row.source_ip,
      first_seen: row.first_seen,
      last_seen: row.last_seen,
      event_count: row.event_count,
      score: row.score,
      confidence: row.confidence,
      confidence_reasons: parseJsonList(row.confidence_reasons_json),
      unique_traps: parseJsonList(row.unique_traps_json),
      protocols: parseJsonList(row.protocols_json),
      last_trap: row.last_trap,
      last_protocol: row.last_protocol
    }))
  });
};
