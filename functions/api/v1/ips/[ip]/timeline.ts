import type { PagesCtx } from "../../../../_lib/env";
import { badRequest, cachedJson, parseSinceHours, publicIp, urlOf } from "../../../../_lib/http";

interface TimelineRow {
  bucket: string;
  count: number;
  max_severity: number;
  max_confidence: number;
}

function bucketExpr(value: string | null): string {
  return value === "day" ? "strftime('%Y-%m-%dT00:00:00.000Z', occurred_at)" : "strftime('%Y-%m-%dT%H:00:00.000Z', occurred_at)";
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.ip) ? ctx.params.ip[0] : ctx.params.ip;
  const ip = publicIp(raw ?? null);
  if (!ip) return badRequest("Invalid IP address.");

  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24 * 7, 24 * 90);
  const bucket = bucketExpr(url.searchParams.get("bucket"));
  const result = await ctx.env.DB.prepare(
    `SELECT ${bucket} AS bucket, COUNT(*) AS count, MAX(severity) AS max_severity, MAX(confidence) AS max_confidence
     FROM events
     WHERE source_ip = ? AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
     GROUP BY bucket
     ORDER BY bucket ASC`
  ).bind(ip, `-${sinceHours} hours`).all<TimelineRow>();

  return cachedJson({ timeline: result.results });
};
