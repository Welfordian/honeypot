import type { PagesCtx } from "../../../_lib/env";
import { enrichIpProfile } from "../../../_lib/enrichment";
import { cachedJson, parseLimit, parseOffset, urlOf } from "../../../_lib/http";
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
  country_code: string | null;
  asn: number | null;
  as_name: string | null;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const limit = parseLimit(url, 100, 500);
  const offset = parseOffset(url);
  const rawEnrichMissing = url.searchParams.get("enrichMissing");
  const enrichMissing =
    rawEnrichMissing === null
      ? 0
      : Math.min(25, Math.max(0, Number.parseInt(rawEnrichMissing, 10) || 0));

  const result = await ctx.env.DB.prepare(
    `SELECT source_ip, first_seen, last_seen, event_count, score, confidence, confidence_reasons_json,
       unique_traps_json, protocols_json, last_trap, last_protocol, country_code, asn, as_name
     FROM ip_profiles
     ORDER BY confidence DESC, score DESC, event_count DESC, last_seen DESC
     LIMIT ? OFFSET ?`
  ).bind(limit + 1, offset).all<IpRow>();
  const rows = result.results.slice(0, limit);

  if (enrichMissing > 0) {
    const missing = rows
      .filter((row) => row.country_code == null && row.asn == null && row.as_name == null)
      .slice(0, enrichMissing);
    for (const row of missing) {
      await enrichIpProfile(ctx.env.DB, row.source_ip, { bucket: ctx.env.EVENTS_BUCKET });
    }
    if (missing.length) {
      const refreshed = await ctx.env.DB.prepare(
        `SELECT source_ip, first_seen, last_seen, event_count, score, confidence, confidence_reasons_json,
           unique_traps_json, protocols_json, last_trap, last_protocol, country_code, asn, as_name
         FROM ip_profiles WHERE source_ip IN (${missing.map(() => "?").join(",")})`
      )
        .bind(...missing.map((row) => row.source_ip))
        .all<IpRow>();
      const byIp = new Map(refreshed.results.map((row) => [row.source_ip, row]));
      for (let i = 0; i < rows.length; i += 1) {
        const updated = byIp.get(rows[i]!.source_ip);
        if (updated) rows[i] = updated;
      }
    }
  }

  return cachedJson({
    ips: rows.map((row) => ({
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
      last_protocol: row.last_protocol,
      country_code: row.country_code,
      asn: row.asn,
      as_name: row.as_name
    })),
    next_offset: result.results.length > limit ? offset + limit : null
  });
};
