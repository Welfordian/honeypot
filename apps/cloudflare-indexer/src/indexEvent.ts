import type { D1Database } from "@cloudflare/workers-types";
import type { MmdbBucket } from "../../../functions/_lib/ipinfoMmdb.js";
import type { LiveEvent, StoredR2Event } from "./types.js";
import { enrichIpProfile } from "../../../functions/_lib/enrichment.js";
import { publicEventRow } from "./publicEvent.js";
import { confidenceForProfile, isOperationalSensorId } from "@honeypot/shared";

interface IpProfileRow {
  first_seen: string;
  last_seen: string;
  event_count: number;
  score: number;
  unique_traps_json: string;
  protocols_json: string;
  confidence: number | null;
  confidence_reasons_json: string | null;
}

function parseList(value: string | null): string[] {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function addUnique(list: string[], value: string): string[] {
  return Array.from(new Set([...list, value])).sort();
}

function liveEventFromRow(row: ReturnType<typeof publicEventRow>): LiveEvent {
  return {
    id: row.id,
    occurred_at: row.occurred_at,
    received_at: row.received_at,
    event_kind: row.event_kind,
    source_ip: row.source_ip,
    source_port: row.source_port,
    destination_port: row.destination_port,
    protocol: row.protocol,
    trap: row.trap,
    sensor_id: row.sensor_id,
    http_method: row.http_method,
    http_path: row.http_path,
    http_status: row.http_status,
    user_agent: row.user_agent,
    credential_kind: row.credential_kind,
    has_credentials: Boolean(row.has_username || row.has_password),
    payload_sha256: row.payload_sha256,
    payload_size: row.payload_size,
    payload_preview: row.payload_preview,
    packet_count: row.packet_count,
    byte_count: row.byte_count,
    tcp_flags: row.tcp_flags,
    is_aggregate: Boolean(row.is_aggregate),
    pcap_sha256: row.pcap_sha256,
    pcap_available: Boolean(row.pcap_available),
    severity: row.severity,
    confidence: row.confidence,
    confidence_reasons: parseList(row.confidence_reasons_json),
    tags: parseList(row.tags_json)
  };
}

function bucketStart(iso: string, width: "hour" | "day"): string {
  const date = new Date(iso);
  if (width === "day") date.setUTCHours(0, 0, 0, 0);
  else date.setUTCMinutes(0, 0, 0);
  return date.toISOString();
}

async function updateProfile(db: D1Database, row: ReturnType<typeof publicEventRow>, bucket?: MmdbBucket): Promise<void> {
  const existing = await db
    .prepare("SELECT first_seen, last_seen, event_count, score, unique_traps_json, protocols_json, confidence, confidence_reasons_json FROM ip_profiles WHERE source_ip = ?")
    .bind(row.source_ip)
    .first<IpProfileRow>();

  if (!existing) {
    const profileConfidence = confidenceForProfile({
      maxEventConfidence: row.confidence,
      eventCount: 1,
      uniqueTraps: [row.trap],
      protocols: [row.protocol],
      eventReasons: parseList(row.confidence_reasons_json)
    });

    await db
      .prepare(
        `INSERT INTO ip_profiles (
          source_ip, first_seen, last_seen, event_count, score, unique_traps_json, protocols_json,
          last_trap, last_protocol, confidence, confidence_reasons_json, updated_at
        ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        row.source_ip,
        row.occurred_at,
        row.occurred_at,
        row.severity,
        JSON.stringify([row.trap]),
        JSON.stringify([row.protocol]),
        row.trap,
        row.protocol,
        profileConfidence.confidence,
        JSON.stringify(profileConfidence.reasons),
        row.indexed_at
      )
      .run();

    try {
      await enrichIpProfile(db, row.source_ip, bucket ? { bucket } : {});
    } catch (error) {
      console.warn("IP enrichment failed", row.source_ip, error);
    }
    return;
  }

  const eventCount = existing.event_count + 1;
  const uniqueTraps = addUnique(parseList(existing.unique_traps_json), row.trap);
  const protocols = addUnique(parseList(existing.protocols_json), row.protocol);
  const profileConfidence = confidenceForProfile({
    maxEventConfidence: Math.max(existing.confidence ?? 0, row.confidence),
    eventCount,
    uniqueTraps,
    protocols,
    eventReasons: [...parseList(existing.confidence_reasons_json), ...parseList(row.confidence_reasons_json)]
  });

  await db
    .prepare(
      `UPDATE ip_profiles SET
        first_seen = ?,
        last_seen = ?,
        event_count = ?,
        score = ?,
        unique_traps_json = ?,
        protocols_json = ?,
        last_trap = ?,
        last_protocol = ?,
        confidence = ?,
        confidence_reasons_json = ?,
        updated_at = ?
      WHERE source_ip = ?`
    )
    .bind(
      existing.first_seen < row.occurred_at ? existing.first_seen : row.occurred_at,
      existing.last_seen > row.occurred_at ? existing.last_seen : row.occurred_at,
      eventCount,
      Math.max(existing.score, row.severity),
      JSON.stringify(uniqueTraps),
      JSON.stringify(protocols),
      row.trap,
      row.protocol,
      profileConfidence.confidence,
      JSON.stringify(profileConfidence.reasons),
      row.indexed_at,
      row.source_ip
    )
    .run();
}

async function updateRollup(db: D1Database, row: ReturnType<typeof publicEventRow>, width: "hour" | "day", dimension: string, key: string): Promise<void> {
  const bucket = bucketStart(row.occurred_at, width);
  await db
    .prepare(
      `INSERT OR IGNORE INTO rollup_unique_ips (bucket_start, bucket_width, dimension, key, source_ip)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(bucket, width, dimension, key, row.source_ip)
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
    .bind(bucket, width, dimension, key, row.indexed_at)
    .run();
}

export async function indexStoredEvent(
  db: D1Database,
  event: StoredR2Event,
  r2Key: string,
  bucket?: MmdbBucket
): Promise<LiveEvent | null> {
  const indexedAt = new Date().toISOString();
  const row = publicEventRow(event, r2Key, indexedAt);

  const insert = await db
    .prepare(
      `INSERT INTO events (
        id, occurred_at, received_at, event_kind, source_ip, source_port, destination_port, protocol, trap, sensor_id,
        http_method, http_path, http_status, user_agent, credential_kind, has_username, has_password,
        payload_sha256, payload_size, payload_preview, packet_count, byte_count, tcp_flags, is_aggregate, pcap_sha256,
        pcap_available, severity, confidence, confidence_reasons_json, tags_json, r2_key, indexed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO NOTHING`
    )
    .bind(
      row.id,
      row.occurred_at,
      row.received_at,
      row.event_kind,
      row.source_ip,
      row.source_port,
      row.destination_port,
      row.protocol,
      row.trap,
      row.sensor_id,
      row.http_method,
      row.http_path,
      row.http_status,
      row.user_agent,
      row.credential_kind,
      row.has_username,
      row.has_password,
      row.payload_sha256,
      row.payload_size,
      row.payload_preview,
      row.packet_count,
      row.byte_count,
      row.tcp_flags,
      row.is_aggregate,
      row.pcap_sha256,
      row.pcap_available,
      row.severity,
      row.confidence,
      row.confidence_reasons_json,
      row.tags_json,
      row.r2_key,
      row.indexed_at
    )
    .run();

  if (!insert.meta.changes) return null;

  await updateProfile(db, row, bucket);

  if (isOperationalSensorId(row.sensor_id)) {
    await db
      .prepare(
        `INSERT INTO sensor_health (sensor_id, last_seen, last_protocol, last_trap, event_count, updated_at)
         VALUES (?, ?, ?, ?, 1, ?)
         ON CONFLICT(sensor_id) DO UPDATE SET
           last_seen = excluded.last_seen,
           last_protocol = excluded.last_protocol,
           last_trap = excluded.last_trap,
           event_count = event_count + 1,
           updated_at = excluded.updated_at`
      )
      .bind(row.sensor_id, row.occurred_at, row.protocol, row.trap, row.indexed_at)
      .run();
  }

  if (row.payload_sha256) {
    await db
      .prepare(
        `INSERT INTO payloads (sha256, size_bytes, mime_guess, preview, first_seen, last_seen, event_count)
         VALUES (?, ?, 'application/octet-stream', ?, ?, ?, 1)
         ON CONFLICT(sha256) DO UPDATE SET
           last_seen = excluded.last_seen,
           event_count = event_count + 1`
      )
      .bind(row.payload_sha256, row.payload_size, row.payload_preview, row.occurred_at, row.occurred_at)
      .run();
  }

  for (const width of ["hour", "day"] as const) {
    await updateRollup(db, row, width, "event_kind", row.event_kind);
    await updateRollup(db, row, width, "protocol", row.protocol);
    await updateRollup(db, row, width, "trap", row.trap);
    await updateRollup(db, row, width, "severity", String(row.severity));
    if (row.destination_port !== null) await updateRollup(db, row, width, "destination_port", String(row.destination_port));
    if (row.tcp_flags) await updateRollup(db, row, width, "tcp_flags", row.tcp_flags);
  }

  return liveEventFromRow(row);
}
