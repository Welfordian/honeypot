export function bucketStart(iso: string, width: "hour" | "day"): string {
  const date = new Date(iso);
  if (width === "day") date.setUTCHours(0, 0, 0, 0);
  else date.setUTCMinutes(0, 0, 0);
  return date.toISOString();
}

export async function touchIngestWatermark(
  db: D1Database,
  occurredAt: string,
  receivedAt: string,
  updatedAt: string
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ingest_watermark (id, last_event_at, last_received_at, updated_at)
       VALUES (1, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         last_event_at = CASE
           WHEN ingest_watermark.last_event_at IS NULL OR excluded.last_event_at > ingest_watermark.last_event_at
           THEN excluded.last_event_at ELSE ingest_watermark.last_event_at END,
         last_received_at = CASE
           WHEN ingest_watermark.last_received_at IS NULL OR excluded.last_received_at > ingest_watermark.last_received_at
           THEN excluded.last_received_at ELSE ingest_watermark.last_received_at END,
         updated_at = excluded.updated_at`
    )
    .bind(occurredAt, receivedAt, updatedAt)
    .run();
}

export async function updateRollup(
  db: D1Database,
  occurredAt: string,
  sourceIp: string,
  indexedAt: string,
  width: "hour" | "day",
  dimension: string,
  key: string
): Promise<void> {
  const bucket = bucketStart(occurredAt, width);
  await db
    .prepare(
      `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(bucket, width, dimension, key, sourceIp)
    .run();

  await db
    .prepare(
      `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
       VALUES (?, ?, ?, ?, 1, 1, ?)
       ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
         count = count + 1,
         unique_ips = (
           SELECT COUNT(*) FROM rollup_unique_ips
           WHERE bucket_start = excluded.bucket_start
             AND bucket_width = excluded.bucket_width
             AND dimension = excluded.dimension
             AND key = excluded.key
         ),
         updated_at = excluded.updated_at`
    )
    .bind(bucket, width, dimension, key, indexedAt)
    .run();
}

export async function sumRollupCounts(
  db: D1Database,
  dimension: string,
  since: string,
  limit: number
): Promise<Array<{ key: string; count: number }>> {
  const result = await db
    .prepare(
      `SELECT key, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY key
       ORDER BY count DESC
       LIMIT ?`
    )
    .bind(dimension, since, limit)
    .all<{ key: string; count: number }>();
  return result.results;
}

export async function sumRollupTimeline(
  db: D1Database,
  since: string
): Promise<Array<{ bucket: string; count: number }>> {
  const result = await db
    .prepare(
      `SELECT bucket_start AS bucket, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = 'event_kind'
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket_start
       ORDER BY bucket_start ASC`
    )
    .bind(since)
    .all<{ bucket: string; count: number }>();
  return result.results;
}

export async function sumRollupEventTotals(
  db: D1Database,
  since: string
): Promise<{ events: number; unique_ips: number }> {
  const [events, uniqueIps] = await Promise.all([
    db
      .prepare(
        `SELECT COALESCE(SUM(count), 0) AS events
         FROM analytics_rollups
         WHERE bucket_width = 'hour'
           AND dimension = 'event_kind'
           AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
      .bind(since)
      .first<{ events: number }>(),
    db
      .prepare(
        `SELECT COUNT(DISTINCT source_ip) AS unique_ips
         FROM rollup_unique_ips
         WHERE bucket_width = 'hour'
           AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
      .bind(since)
      .first<{ unique_ips: number }>()
  ]);

  return {
    events: events?.events ?? 0,
    unique_ips: uniqueIps?.unique_ips ?? 0
  };
}
