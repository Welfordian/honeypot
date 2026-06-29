import type { PagesCtx } from "../../../../_lib/env";
import { badRequest, cachedJson, parseSinceHours, publicSha256, urlOf } from "../../../../_lib/http";

interface TimelineRow {
  bucket: string;
  count: number;
  unique_ips: number;
  max_severity: number;
  max_confidence: number;
}

function bucketExpr(value: string | null): string {
  return value === "day" ? "strftime('%Y-%m-%dT00:00:00.000Z', occurred_at)" : "strftime('%Y-%m-%dT%H:00:00.000Z', occurred_at)";
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const raw = Array.isArray(ctx.params.sha256) ? ctx.params.sha256[0] : ctx.params.sha256;
  const sha256 = publicSha256(raw ?? null);
  if (!sha256) return badRequest("Invalid SHA-256 hash.");

  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24 * 7, 24 * 90);
  const bucket = bucketExpr(url.searchParams.get("bucket"));
  const result = await ctx.env.DB.prepare(
    `SELECT ${bucket} AS bucket, COUNT(*) AS count, COUNT(DISTINCT source_ip) AS unique_ips,
       MAX(severity) AS max_severity, MAX(confidence) AS max_confidence
     FROM events
     WHERE payload_sha256 = ? AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
     GROUP BY bucket
     ORDER BY bucket ASC`
  ).bind(sha256, `-${sinceHours} hours`).all<TimelineRow>();

  return cachedJson({ timeline: result.results });
};
