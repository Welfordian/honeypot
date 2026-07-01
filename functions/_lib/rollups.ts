export const FAST_CACHE = {
  headers: { "cache-control": "public, max-age=120, stale-while-revalidate=600" }
};

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

export async function updateRollupAmount(
  db: D1Database,
  occurredAt: string,
  indexedAt: string,
  width: "hour" | "day",
  dimension: string,
  key: string,
  amount: number
): Promise<void> {
  if (amount <= 0) return;
  const bucket = bucketStart(occurredAt, width);
  await db
    .prepare(
      `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, ?)
       ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
         count = count + excluded.count,
         updated_at = excluded.updated_at`
    )
    .bind(bucket, width, dimension, key, amount, indexedAt)
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

export async function sumRollupCountsForKeys(
  db: D1Database,
  dimension: string,
  keys: string[],
  since: string
): Promise<Array<{ key: string; count: number }>> {
  if (!keys.length) return [];
  const placeholders = keys.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT key, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND key IN (${placeholders})
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY key
       ORDER BY count DESC`
    )
    .bind(dimension, ...keys, since)
    .all<{ key: string; count: number }>();
  return result.results;
}

export async function sumRollupDimensionTotal(
  db: D1Database,
  dimension: string,
  since: string
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COALESCE(SUM(count), 0) AS events
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(dimension, since)
    .first<{ events: number }>();
  return row?.events ?? 0;
}

export async function sumRollupCountsWithUniqueIps(
  db: D1Database,
  dimension: string,
  since: string,
  limit: number
): Promise<Array<{ key: string; count: number; unique_ips: number }>> {
  const result = await db
    .prepare(
      `SELECT r.key,
              SUM(r.count) AS count,
              (
                SELECT COUNT(DISTINCT u.source_ip)
                FROM rollup_unique_ips u
                WHERE u.bucket_width = 'hour'
                  AND u.dimension = ?
                  AND u.key = r.key
                  AND u.bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
              ) AS unique_ips
       FROM analytics_rollups r
       WHERE r.bucket_width = 'hour'
         AND r.dimension = ?
         AND r.bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY r.key
       ORDER BY count DESC
       LIMIT ?`
    )
    .bind(dimension, since, dimension, since, limit)
    .all<{ key: string; count: number; unique_ips: number }>();
  return result.results;
}

export async function sumRollupCountForKey(
  db: D1Database,
  dimension: string,
  key: string,
  since: string
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COALESCE(SUM(count), 0) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND key = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(dimension, key, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function sumRollupAmountForKey(
  db: D1Database,
  dimension: string,
  key: string,
  since: string
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COALESCE(SUM(count), 0) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND key = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(dimension, key, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function sumRollupTimeline(
  db: D1Database,
  since: string,
  dimension = "event_kind"
): Promise<Array<{ bucket: string; count: number }>> {
  const result = await db
    .prepare(
      `SELECT bucket_start AS bucket, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket_start
       ORDER BY bucket_start ASC`
    )
    .bind(dimension, since)
    .all<{ bucket: string; count: number }>();
  return result.results;
}

export async function sumRollupTimelineForKinds(
  db: D1Database,
  since: string,
  kinds: string[]
): Promise<Array<{ bucket: string; count: number }>> {
  if (!kinds.length) return [];
  const placeholders = kinds.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT bucket_start AS bucket, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = 'event_kind'
         AND key IN (${placeholders})
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket_start
       ORDER BY bucket_start ASC`
    )
    .bind(...kinds, since)
    .all<{ bucket: string; count: number }>();
  return result.results;
}

export async function sumRollupTimelineWithUniqueIpsForKinds(
  db: D1Database,
  since: string,
  kinds: string[]
): Promise<Array<{ bucket: string; count: number; unique_ips: number }>> {
  if (!kinds.length) return [];
  const placeholders = kinds.map(() => "?").join(", ");

  const [counts, uniqueIps] = await Promise.all([
    sumRollupTimelineForKinds(db, since, kinds),
    db
      .prepare(
        `SELECT bucket_start AS bucket, COUNT(DISTINCT source_ip) AS unique_ips
         FROM rollup_unique_ips
         WHERE bucket_width = 'hour'
           AND dimension = 'event_kind'
           AND key IN (${placeholders})
           AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         GROUP BY bucket_start
         ORDER BY bucket_start ASC`
      )
      .bind(...kinds, since)
      .all<{ bucket: string; unique_ips: number }>()
  ]);

  const ipsByBucket = new Map(uniqueIps.results.map((row) => [row.bucket, row.unique_ips]));
  return counts.map((row) => ({
    bucket: row.bucket,
    count: row.count,
    unique_ips: ipsByBucket.get(row.bucket) ?? 0
  }));
}

export async function sumRollupTimelineForKeys(
  db: D1Database,
  dimension: string,
  keys: string[],
  since: string
): Promise<Array<{ key: string; bucket: string; count: number }>> {
  if (!keys.length) return [];
  const placeholders = keys.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT key, bucket_start AS bucket, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND key IN (${placeholders})
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY key, bucket_start
       ORDER BY bucket_start ASC`
    )
    .bind(dimension, ...keys, since)
    .all<{ key: string; bucket: string; count: number }>();
  return result.results;
}

export async function countRollupDistinctIps(
  db: D1Database,
  dimension: string,
  since: string
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(DISTINCT source_ip) AS count
       FROM rollup_unique_ips
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(dimension, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function maxProfileSeverity(
  db: D1Database,
  since: string
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COALESCE(MAX(CAST(key AS INTEGER)), 0) AS max_severity
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = 'severity'
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND count > 0`
    )
    .bind(since)
    .first<{ max_severity: number }>();
  return row?.max_severity ?? 0;
}

export async function exampleIpsForRollupKey(
  db: D1Database,
  dimension: string,
  key: string,
  since: string,
  limit: number
): Promise<string[]> {
  const result = await db
    .prepare(
      `SELECT source_ip
       FROM rollup_unique_ips
       WHERE bucket_width = 'hour'
         AND dimension = ?
         AND key = ?
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY source_ip
       ORDER BY COUNT(*) DESC, source_ip ASC
       LIMIT ?`
    )
    .bind(dimension, key, since, limit)
    .all<{ source_ip: string }>();
  return result.results.map((row) => row.source_ip);
}

interface WindowIpStats {
  source_ip: string;
  max_severity: number;
  max_confidence: number;
  first_seen: string;
  last_seen: string;
}

async function windowStatsForIps(
  db: D1Database,
  since: string,
  ips: string[]
): Promise<Map<string, WindowIpStats>> {
  if (!ips.length) return new Map();
  const placeholders = ips.map(() => "?").join(", ");
  const result = await db
    .prepare(
      `SELECT source_ip,
              MAX(severity) AS max_severity,
              MAX(confidence) AS max_confidence,
              MIN(occurred_at) AS first_seen,
              MAX(occurred_at) AS last_seen
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND source_ip IN (${placeholders})
       GROUP BY source_ip`
    )
    .bind(since, ...ips)
    .all<WindowIpStats>();
  return new Map(result.results.map((row) => [row.source_ip, row]));
}

async function topAttackersFromEvents(
  db: D1Database,
  since: string,
  limit: number
): Promise<
  Array<{
    key: string;
    count: number;
    max_severity: number;
    max_confidence: number;
    first_seen: string;
    last_seen: string;
  }>
> {
  const fallback = await db
    .prepare(
      `SELECT source_ip AS key,
              COUNT(*) AS count,
              MAX(severity) AS max_severity,
              MAX(confidence) AS max_confidence,
              MIN(occurred_at) AS first_seen,
              MAX(occurred_at) AS last_seen
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY source_ip
       ORDER BY count DESC, max_confidence DESC, last_seen DESC
       LIMIT ?`
    )
    .bind(since, limit)
    .all<{
      key: string;
      count: number;
      max_severity: number;
      max_confidence: number;
      first_seen: string;
      last_seen: string;
    }>();
  return fallback.results;
}

export async function topAttackersInWindow(
  db: D1Database,
  since: string,
  limit: number
): Promise<
  Array<{
    key: string;
    count: number;
    max_severity: number;
    max_confidence: number;
    first_seen: string;
    last_seen: string;
  }>
> {
  const [windowTotals, attackerRollupEvents] = await Promise.all([
    sumRollupEventTotals(db, since),
    sumRollupDimensionTotal(db, "attacker_ip", since)
  ]);

  const rollupsComplete =
    windowTotals.events > 0 && attackerRollupEvents >= windowTotals.events * 0.99;

  if (!rollupsComplete) {
    return topAttackersFromEvents(db, since, limit);
  }

  const ranked = await db
    .prepare(
      `SELECT key, SUM(count) AS count
       FROM analytics_rollups
       WHERE bucket_width = 'hour'
         AND dimension = 'attacker_ip'
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY key
       ORDER BY count DESC, key ASC
       LIMIT ?`
    )
    .bind(since, limit)
    .all<{ key: string; count: number }>();

  if (ranked.results.length === 0) {
    return topAttackersFromEvents(db, since, limit);
  }

  const statsByIp = await windowStatsForIps(
    db,
    since,
    ranked.results.map((row) => row.key)
  );
  return ranked.results.map((row) => {
    const stats = statsByIp.get(row.key);
    return {
      key: row.key,
      count: row.count,
      max_severity: stats?.max_severity ?? 0,
      max_confidence: stats?.max_confidence ?? 0,
      first_seen: stats?.first_seen ?? "",
      last_seen: stats?.last_seen ?? ""
    };
  });
}

/** @deprecated Prefer topAttackersInWindow for window-accurate counts. */
export async function topIpProfiles(
  db: D1Database,
  since: string,
  limit: number
): Promise<
  Array<{
    key: string;
    count: number;
    max_severity: number;
    max_confidence: number;
    first_seen: string;
    last_seen: string;
  }>
> {
  return topAttackersInWindow(db, since, limit);
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

export async function sumRollupEventTotalsForKinds(
  db: D1Database,
  since: string,
  kinds: string[]
): Promise<{ events: number; unique_ips: number }> {
  if (!kinds.length) return { events: 0, unique_ips: 0 };
  const placeholders = kinds.map(() => "?").join(", ");

  const [events, uniqueIps] = await Promise.all([
    db
      .prepare(
        `SELECT COALESCE(SUM(count), 0) AS events
         FROM analytics_rollups
         WHERE bucket_width = 'hour'
           AND dimension = 'event_kind'
           AND key IN (${placeholders})
           AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
      .bind(...kinds, since)
      .first<{ events: number }>(),
    db
      .prepare(
        `SELECT COUNT(DISTINCT source_ip) AS unique_ips
         FROM rollup_unique_ips
         WHERE bucket_width = 'hour'
           AND dimension = 'event_kind'
           AND key IN (${placeholders})
           AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
      .bind(...kinds, since)
      .first<{ unique_ips: number }>()
  ]);

  return {
    events: events?.events ?? 0,
    unique_ips: uniqueIps?.unique_ips ?? 0
  };
}

export async function topPayloadCampaigns(
  db: D1Database,
  since: string,
  limit: number
): Promise<
  Array<{
    sha256: string;
    event_count: number;
    unique_ips: number;
    max_confidence: number;
  }>
> {
  const result = await db
    .prepare(
      `SELECT payload_sha256 AS sha256,
              COUNT(*) AS event_count,
              COUNT(DISTINCT source_ip) AS unique_ips,
              MAX(confidence) AS max_confidence
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND payload_sha256 IS NOT NULL
       GROUP BY payload_sha256
       HAVING event_count >= 2
       ORDER BY event_count DESC, max_confidence DESC
       LIMIT ?`
    )
    .bind(since, limit)
    .all<{ sha256: string; event_count: number; unique_ips: number; max_confidence: number }>();
  return result.results;
}
