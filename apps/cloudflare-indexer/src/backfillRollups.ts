import type { Env } from "./types.js";
import { attackTechniqueIds } from "../../../functions/_lib/attackMapping.js";
import { parseJsonList } from "../../../functions/_lib/rows.js";

const UPSERT_ROLLUP = `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
VALUES (?, 'hour', ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
  count = excluded.count,
  unique_ips = excluded.unique_ips,
  updated_at = excluded.updated_at`;

interface EventTechniqueRow {
  source_ip: string;
  occurred_at: string;
  protocol: string;
  trap: string;
  http_path: string | null;
  has_username: number;
  has_password: number;
  confidence_reasons_json: string;
}

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

async function backfillTechniquesForDay(db: Env["DB"], dayOffset: number): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  const rows = await db
    .prepare(
      `SELECT source_ip, occurred_at, protocol, trap, http_path,
              has_username, has_password, confidence_reasons_json
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(startOffset, endOffset)
    .all<EventTechniqueRow>();

  const buckets = new Map<string, { bucket_start: string; key: string; count: number; ips: Set<string> }>();
  for (const row of rows.results) {
    const bucketStart = `${row.occurred_at.slice(0, 13)}:00:00.000Z`;
    const techniques = attackTechniqueIds({
      protocol: row.protocol,
      trap: row.trap,
      http_path: row.http_path,
      has_credentials: Boolean(row.has_username || row.has_password),
      confidence_reasons: parseJsonList(row.confidence_reasons_json)
    });

    for (const techniqueId of techniques) {
      const bucketKey = `${bucketStart}\u0000${techniqueId}`;
      const bucket = buckets.get(bucketKey) ?? {
        bucket_start: bucketStart,
        key: techniqueId,
        count: 0,
        ips: new Set<string>()
      };
      bucket.count += 1;
      bucket.ips.add(row.source_ip);
      buckets.set(bucketKey, bucket);
    }
  }

  for (const bucket of buckets.values()) {
    await db
      .prepare(UPSERT_ROLLUP)
      .bind(bucket.bucket_start, "attack_technique", bucket.key, bucket.count, bucket.ips.size)
      .run();
  }

  return buckets.size;
}

export async function backfillRollups(
  env: Env,
  days = 30
): Promise<{ days: number; tag_buckets: number; reason_buckets: number; technique_buckets: number }> {
  let tagBuckets = 0;
  let reasonBuckets = 0;
  let techniqueBuckets = 0;

  for (let day = 0; day < days; day += 1) {
    tagBuckets += await backfillDimensionForDay(env.DB, "tag", "tags_json", day);
    reasonBuckets += await backfillDimensionForDay(env.DB, "confidence_reason", "confidence_reasons_json", day);
    techniqueBuckets += await backfillTechniquesForDay(env.DB, day);
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO ingest_watermark (id, last_event_at, last_received_at, updated_at)
     VALUES (1, NULL, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`
  ).run();
  await env.DB.prepare(
    `UPDATE ingest_watermark
     SET
       last_event_at = (SELECT MAX(occurred_at) FROM events),
       last_received_at = (SELECT MAX(received_at) FROM events),
       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE id = 1`
  ).run();

  return { days, tag_buckets: tagBuckets, reason_buckets: reasonBuckets, technique_buckets: techniqueBuckets };
}
