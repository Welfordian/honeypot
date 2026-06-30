import type { PagesCtx } from "../../../_lib/env";
import { badRequest, cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";

const BUCKET_WIDTHS = new Set(["hour", "day"]);
const DIMENSIONS = new Set([
  "protocol",
  "trap",
  "event_kind",
  "severity",
  "destination_port",
  "tcp_flags"
]);

interface RollupRow {
  bucket_start: string;
  key: string;
  count: number;
  unique_ips: number;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 168, 24 * 30);
  const bucketWidth = url.searchParams.get("bucketWidth") ?? "hour";
  const dimension = url.searchParams.get("dimension") ?? "protocol";

  if (!BUCKET_WIDTHS.has(bucketWidth)) {
    return badRequest("bucketWidth must be hour or day.");
  }
  if (!DIMENSIONS.has(dimension)) {
    return badRequest("Invalid dimension.");
  }

  const since = `-${sinceHours} hours`;
  const result = await ctx.env.DB.prepare(
    `SELECT bucket_start, key, count, unique_ips
     FROM analytics_rollups
     WHERE bucket_width = ?
       AND dimension = ?
       AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
     ORDER BY bucket_start ASC, key ASC`
  )
    .bind(bucketWidth, dimension, since)
    .all<RollupRow>();

  const byKey = new Map<string, Array<{ bucket: string; count: number; unique_ips: number }>>();
  for (const row of result.results) {
    const points = byKey.get(row.key) ?? [];
    points.push({
      bucket: row.bucket_start,
      count: row.count,
      unique_ips: row.unique_ips
    });
    byKey.set(row.key, points);
  }

  const series = [...byKey.entries()]
    .map(([key, points]) => ({
      key,
      points,
      total: points.reduce((sum, point) => sum + point.count, 0)
    }))
    .sort((a, b) => b.total - a.total)
    .map(({ key, points }) => ({ key, points }));

  return cachedJson({
    dimension,
    bucketWidth,
    sinceHours,
    series
  });
};
