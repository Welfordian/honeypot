import type { Env } from "./types.js";

const UPSERT_ROLLUP = `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
VALUES (?, 'hour', ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
  count = analytics_rollups.count + excluded.count,
  unique_ips = MAX(analytics_rollups.unique_ips, excluded.unique_ips),
  updated_at = excluded.updated_at`;

async function backfillDimensionForDay(
  db: Env["DB"],
  dimension: "tag" | "confidence_reason",
  jsonColumn: "tags_json" | "confidence_reasons_json",
  dayOffset: number
): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;

  const rows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         j.value AS key,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips
       FROM events, json_each(events.${jsonColumn}) AS j
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket_start, j.value`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; key: string; count: number; unique_ips: number }>();

  for (const row of rows.results) {
    if (!row.key) continue;
    await db
      .prepare(UPSERT_ROLLUP)
      .bind(row.bucket_start, dimension, row.key, row.count, row.unique_ips)
      .run();
  }

  return rows.results.length;
}

export async function backfillRollups(
  env: Env,
  days = 30
): Promise<{ days: number; tag_buckets: number; reason_buckets: number }> {
  let tagBuckets = 0;
  let reasonBuckets = 0;

  for (let day = 0; day < days; day += 1) {
    tagBuckets += await backfillDimensionForDay(env.DB, "tag", "tags_json", day);
    reasonBuckets += await backfillDimensionForDay(env.DB, "confidence_reason", "confidence_reasons_json", day);
  }

  await env.DB.prepare(
    `INSERT INTO ingest_watermark (id, last_event_at, last_received_at, updated_at)
     SELECT 1, MAX(occurred_at), MAX(received_at), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     FROM events
     ON CONFLICT(id) DO UPDATE SET
       last_event_at = excluded.last_event_at,
       last_received_at = excluded.last_received_at,
       updated_at = excluded.updated_at`
  ).run();

  return { days, tag_buckets: tagBuckets, reason_buckets: reasonBuckets };
}
