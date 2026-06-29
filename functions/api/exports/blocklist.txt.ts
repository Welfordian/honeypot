import type { PagesCtx } from "../../_lib/env";
import { parseLimit, text, urlOf } from "../../_lib/http";

interface IpRow {
  source_ip: string;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const minScore = Math.max(1, Math.min(10, Number(url.searchParams.get("minScore") ?? 6)));
  const limit = parseLimit(url, 10000, 10000);
  const result = await ctx.env.DB.prepare(
    `SELECT source_ip
     FROM ip_profiles
     WHERE score >= ?
     ORDER BY score DESC, event_count DESC, last_seen DESC
     LIMIT ?`
  ).bind(minScore, limit).all<IpRow>();
  return text(`${result.results.map((row) => row.source_ip).join("\n")}\n`);
};
