import type { PagesCtx } from "../../../_lib/env";
import { badRequest, cachedJson, urlOf } from "../../../_lib/http";
import { parseJsonList } from "../../../_lib/rows";

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

function parseSinceIso(value: string | null): string | Response {
  if (!value?.trim()) return badRequest("since is required (ISO8601 timestamp).");
  const parsed = Date.parse(value.trim());
  if (!Number.isFinite(parsed)) return badRequest("Invalid since timestamp.");
  return new Date(parsed).toISOString();
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const since = parseSinceIso(url.searchParams.get("since"));
  if (since instanceof Response) return since;

  const result = await ctx.env.DB.prepare(
    `SELECT source_ip, first_seen, last_seen, event_count, score, confidence, confidence_reasons_json,
       unique_traps_json, protocols_json, last_trap, last_protocol
     FROM ip_profiles
     WHERE first_seen >= ?
     ORDER BY first_seen DESC
     LIMIT 5000`
  )
    .bind(since)
    .all<IpRow>();

  return cachedJson({
    since,
    count: result.results.length,
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
