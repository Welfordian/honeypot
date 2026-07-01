import type { Env } from "./types.js";
import { attackTechniqueIds } from "../../../functions/_lib/attackMapping.js";
import { isExploitHttpPath } from "@honeypot/shared";

const UPSERT_ROLLUP = `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
VALUES (?, 'hour', ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
  count = analytics_rollups.count + excluded.count,
  unique_ips = MAX(analytics_rollups.unique_ips, excluded.unique_ips),
  updated_at = excluded.updated_at`;

const UPSERT_ROLLUP_AMOUNT = `INSERT INTO analytics_rollups (bucket_start, bucket_width, dimension, key, count, unique_ips, updated_at)
VALUES (?, 'hour', ?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(bucket_start, bucket_width, dimension, key) DO UPDATE SET
  count = analytics_rollups.count + excluded.count,
  updated_at = excluded.updated_at`;

const INSERT_UNIQUE_IP = `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
VALUES (?, 'hour', ?, ?, ?)`;

async function backfillUniqueIpsJsonForDay(
  db: Env["DB"],
  dimension: "tag" | "confidence_reason",
  jsonColumn: "tags_json" | "confidence_reasons_json",
  dayOffset: number
): Promise<void> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;

  await db
    .prepare(
      `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
       SELECT substr(occurred_at, 1, 13) || ':00:00.000Z', 'hour', ?, j.value, source_ip
       FROM events, json_each(events.${jsonColumn}) AS j
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY 1, 2, 3, 4, 5`
    )
    .bind(dimension, startOffset, endOffset)
    .run();
}

async function backfillUniqueIpsScalarForDay(
  db: Env["DB"],
  dimension: string,
  column: string,
  dayOffset: number,
  whereClause = ""
): Promise<void> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  const where = whereClause ? `AND ${whereClause}` : "";

  await db
    .prepare(
      `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
       SELECT substr(occurred_at, 1, 13) || ':00:00.000Z', 'hour', ?, CAST(${column} AS TEXT), source_ip
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND ${column} IS NOT NULL
         ${where}
       GROUP BY 1, 2, 3, 4, 5`
    )
    .bind(dimension, startOffset, endOffset)
    .run();
}

async function backfillUniqueIpsConstantKeyForDay(
  db: Env["DB"],
  dimension: string,
  key: string,
  dayOffset: number,
  whereClause: string
): Promise<void> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;

  await db
    .prepare(
      `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
       SELECT substr(occurred_at, 1, 13) || ':00:00.000Z', 'hour', ?, ?, source_ip
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND ${whereClause}
       GROUP BY 1, 2, 3, 4, 5`
    )
    .bind(dimension, key, startOffset, endOffset)
    .run();
}

async function syncRollupUniqueIpCounts(db: Env["DB"], days: number): Promise<void> {
  const since = `-${days} days`;
  await db
    .prepare(
      `UPDATE analytics_rollups
       SET unique_ips = COALESCE((
         SELECT COUNT(*)
         FROM rollup_unique_ips u
         WHERE u.bucket_start = analytics_rollups.bucket_start
           AND u.bucket_width = analytics_rollups.bucket_width
           AND u.dimension = analytics_rollups.dimension
           AND u.key = analytics_rollups.key
       ), 0)
       WHERE bucket_width = 'hour'
         AND bucket_start >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(since)
    .run();
}

async function backfillJsonDimensionForDay(
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
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, dimension, row.key, row.count, row.unique_ips).run();
  }

  await backfillUniqueIpsJsonForDay(db, dimension, jsonColumn, dayOffset);

  return rows.results.length;
}

async function backfillConstantKeyDimensionForDay(
  db: Env["DB"],
  dimension: string,
  key: string,
  dayOffset: number,
  whereClause: string
): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;

  const rows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND ${whereClause}
       GROUP BY bucket_start`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; count: number; unique_ips: number }>();

  for (const row of rows.results) {
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, dimension, key, row.count, row.unique_ips).run();
  }

  await backfillUniqueIpsConstantKeyForDay(db, dimension, key, dayOffset, whereClause);

  return rows.results.length;
}

async function backfillScalarDimensionForDay(
  db: Env["DB"],
  dimension: string,
  column: string,
  dayOffset: number,
  whereClause = ""
): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  const where = whereClause ? `AND ${whereClause}` : "";

  const rows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         CAST(${column} AS TEXT) AS key,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND ${column} IS NOT NULL
         ${where}
       GROUP BY bucket_start, key`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; key: string; count: number; unique_ips: number }>();

  for (const row of rows.results) {
    if (!row.key) continue;
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, dimension, row.key, row.count, row.unique_ips).run();
  }

  await backfillUniqueIpsScalarForDay(db, dimension, column, dayOffset, whereClause);

  return rows.results.length;
}

async function backfillHttpDimensionsForDay(db: Env["DB"], dayOffset: number): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  let buckets = 0;

  const pathRows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         http_path AS key,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips,
         SUM(CASE WHEN has_username = 1 OR has_password = 1 THEN 1 ELSE 0 END) AS credential_count,
         SUM(CASE WHEN has_username = 1 OR has_password = 1 THEN 1 ELSE 0 END) AS credential_unique
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND protocol IN ('http', 'https')
         AND http_path IS NOT NULL
         AND http_path != ''
       GROUP BY bucket_start, http_path`
    )
    .bind(startOffset, endOffset)
    .all<{
      bucket_start: string;
      key: string;
      count: number;
      unique_ips: number;
      credential_count: number;
      credential_unique: number;
    }>();

  for (const row of pathRows.results) {
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, "http_path", row.key, row.count, row.unique_ips).run();
    buckets += 1;
    if (isExploitHttpPath(row.key)) {
      await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, "http_exploit_path", row.key, row.count, row.unique_ips).run();
      buckets += 1;
    }
  }

  const credentialRows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         http_path AS key,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND protocol IN ('http', 'https')
         AND http_path IS NOT NULL
         AND http_path != ''
         AND (has_username = 1 OR has_password = 1)
       GROUP BY bucket_start, http_path`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; key: string; count: number; unique_ips: number }>();

  for (const row of credentialRows.results) {
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, "http_credential_path", row.key, row.count, row.unique_ips).run();
    buckets += 1;
  }

  const uaRows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         substr(user_agent, 1, 120) AS key,
         COUNT(*) AS count,
         COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND protocol IN ('http', 'https')
         AND user_agent IS NOT NULL
         AND user_agent != ''
       GROUP BY bucket_start, key`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; key: string; count: number; unique_ips: number }>();

  for (const row of uaRows.results) {
    await db.prepare(UPSERT_ROLLUP).bind(row.bucket_start, "http_user_agent", row.key, row.count, row.unique_ips).run();
    buckets += 1;
  }

  const httpWhere = "protocol IN ('http', 'https') AND http_path IS NOT NULL AND http_path != ''";
  await backfillUniqueIpsScalarForDay(db, "http_path", "http_path", dayOffset, httpWhere);
  await backfillUniqueIpsScalarForDay(
    db,
    "http_credential_path",
    "http_path",
    dayOffset,
    `${httpWhere} AND (has_username = 1 OR has_password = 1)`
  );
  await backfillUniqueIpsScalarForDay(
    db,
    "http_user_agent",
    "user_agent",
    dayOffset,
    "protocol IN ('http', 'https') AND user_agent IS NOT NULL AND user_agent != ''"
  );

  return buckets;
}

async function backfillNetworkDimensionsForDay(db: Env["DB"], dayOffset: number): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  let buckets = 0;

  const scalarDimensions: Array<{ dimension: string; column: string; where?: string }> = [
    { dimension: "net_protocol", column: "protocol", where: "event_kind IN ('network-attempt', 'tcp-banner')" },
    { dimension: "net_destination_port", column: "destination_port", where: "event_kind IN ('network-attempt', 'tcp-banner')" },
    { dimension: "net_tcp_flags", column: "tcp_flags", where: "event_kind IN ('network-attempt', 'tcp-banner')" },
    { dimension: "net_banner_ip", column: "source_ip", where: "event_kind = 'tcp-banner'" }
  ];

  for (const { dimension, column, where } of scalarDimensions) {
    buckets += await backfillScalarDimensionForDay(db, dimension, column, dayOffset, where);
  }

  const amountRows = await db
    .prepare(
      `SELECT
         substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket_start,
         COALESCE(SUM(packet_count), 0) AS packets,
         COALESCE(SUM(byte_count), 0) AS bytes,
         SUM(CASE WHEN is_aggregate = 1 THEN 1 ELSE 0 END) AS aggregates
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND event_kind IN ('network-attempt', 'tcp-banner')
       GROUP BY bucket_start`
    )
    .bind(startOffset, endOffset)
    .all<{ bucket_start: string; packets: number; bytes: number; aggregates: number }>();

  for (const row of amountRows.results) {
    if (row.packets > 0) {
      await db.prepare(UPSERT_ROLLUP_AMOUNT).bind(row.bucket_start, "net_packets", "total", row.packets).run();
      buckets += 1;
    }
    if (row.bytes > 0) {
      await db.prepare(UPSERT_ROLLUP_AMOUNT).bind(row.bucket_start, "net_bytes", "total", row.bytes).run();
      buckets += 1;
    }
    if (row.aggregates > 0) {
      await db.prepare(UPSERT_ROLLUP_AMOUNT).bind(row.bucket_start, "net_aggregate", "1", row.aggregates).run();
      buckets += 1;
    }
  }

  return buckets;
}

async function backfillAttackTechniquesForDay(db: Env["DB"], dayOffset: number): Promise<number> {
  const startOffset = `-${dayOffset + 1} days`;
  const endOffset = `-${dayOffset} days`;
  let buckets = 0;

  const events = await db
    .prepare(
      `SELECT occurred_at, source_ip, protocol, trap, http_path, has_username, has_password, confidence_reasons_json
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         AND occurred_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    )
    .bind(startOffset, endOffset)
    .all<{
      occurred_at: string;
      source_ip: string;
      protocol: string;
      trap: string;
      http_path: string | null;
      has_username: number;
      has_password: number;
      confidence_reasons_json: string;
    }>();

  const bucketCounts = new Map<string, { count: number; ips: Set<string> }>();

  for (const event of events.results) {
    let reasons: string[] = [];
    try {
      const parsed = JSON.parse(event.confidence_reasons_json || "[]");
      reasons = Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
    } catch {
      reasons = [];
    }

    const techniqueIds = attackTechniqueIds({
      protocol: event.protocol,
      trap: event.trap,
      http_path: event.http_path,
      has_credentials: Boolean(event.has_username || event.has_password),
      confidence_reasons: reasons
    });

    const bucket = `${event.occurred_at.slice(0, 13)}:00:00.000Z`;
    for (const techniqueId of techniqueIds) {
      const mapKey = `${bucket}\0${techniqueId}`;
      const entry = bucketCounts.get(mapKey) ?? { count: 0, ips: new Set<string>() };
      entry.count += 1;
      entry.ips.add(event.source_ip);
      bucketCounts.set(mapKey, entry);
    }
  }

  for (const [mapKey, entry] of bucketCounts) {
    const [bucket, techniqueId] = mapKey.split("\0");
    for (const ip of entry.ips) {
      await db.prepare(INSERT_UNIQUE_IP).bind(bucket, "attack_technique", techniqueId, ip).run();
    }
    await db
      .prepare(UPSERT_ROLLUP)
      .bind(bucket, "attack_technique", techniqueId, entry.count, entry.ips.size)
      .run();
    buckets += 1;
  }

  return buckets;
}

export async function backfillRollups(
  env: Env,
  days = 30
): Promise<{
  days: number;
  tag_buckets: number;
  reason_buckets: number;
  scalar_buckets: number;
  http_buckets: number;
  network_buckets: number;
  technique_buckets: number;
}> {
  let tagBuckets = 0;
  let reasonBuckets = 0;
  let scalarBuckets = 0;
  let httpBuckets = 0;
  let networkBuckets = 0;
  let techniqueBuckets = 0;

  const scalarDimensions: Array<{ dimension: string; column: string; where?: string }> = [
    { dimension: "event_kind", column: "event_kind" },
    { dimension: "attacker_ip", column: "source_ip" },
    { dimension: "protocol", column: "protocol" },
    { dimension: "trap", column: "trap" },
    { dimension: "severity", column: "severity" },
    { dimension: "destination_port", column: "destination_port" },
    { dimension: "tcp_flags", column: "tcp_flags" }
  ];

  for (let day = 0; day < days; day += 1) {
    tagBuckets += await backfillJsonDimensionForDay(env.DB, "tag", "tags_json", day);
    reasonBuckets += await backfillJsonDimensionForDay(env.DB, "confidence_reason", "confidence_reasons_json", day);
    for (const { dimension, column, where } of scalarDimensions) {
      scalarBuckets += await backfillScalarDimensionForDay(env.DB, dimension, column, day, where);
    }
    scalarBuckets += await backfillConstantKeyDimensionForDay(
      env.DB,
      "has_credentials",
      "1",
      day,
      "(has_username = 1 OR has_password = 1)"
    );
    scalarBuckets += await backfillScalarDimensionForDay(
      env.DB,
      "high_confidence_ip",
      "source_ip",
      day,
      "confidence >= 80"
    );
    httpBuckets += await backfillHttpDimensionsForDay(env.DB, day);
    networkBuckets += await backfillNetworkDimensionsForDay(env.DB, day);
    techniqueBuckets += await backfillAttackTechniquesForDay(env.DB, day);
  }

  await syncRollupUniqueIpCounts(env.DB, days);

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

  return {
    days,
    tag_buckets: tagBuckets,
    reason_buckets: reasonBuckets,
    scalar_buckets: scalarBuckets,
    http_buckets: httpBuckets,
    network_buckets: networkBuckets,
    technique_buckets: techniqueBuckets
  };
}
