import type { D1Database } from "@cloudflare/workers-types";
import type { MmdbBucket } from "../../../functions/_lib/ipinfoMmdb.js";
import type { LiveEvent, StoredR2Event } from "./types.js";
import { enrichIpProfile } from "../../../functions/_lib/enrichment.js";
import { attackTechniqueIds } from "../../../functions/_lib/attackMapping.js";
import { touchIngestWatermark, updateRollup } from "../../../functions/_lib/rollups.js";
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

const HTTP_UA_TRUNCATE = 120;
const NETWORK_KINDS = new Set(["network-attempt", "tcp-banner"]);

function isHttpProtocol(protocol: string): boolean {
  const lower = protocol.toLowerCase();
  return lower === "http" || lower === "https";
}

async function indexRollups(db: D1Database, row: ReturnType<typeof publicEventRow>): Promise<void> {
  const techniqueInput = {
    protocol: row.protocol,
    trap: row.trap,
    http_path: row.http_path,
    has_credentials: Boolean(row.has_username || row.has_password),
    confidence_reasons: parseList(row.confidence_reasons_json)
  };

  for (const width of ["hour", "day"] as const) {
    await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "event_kind", row.event_kind);
    await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "protocol", row.protocol);
    await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "trap", row.trap);
    await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "severity", String(row.severity));

    if (row.destination_port !== null) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "destination_port", String(row.destination_port));
    }
    if (row.tcp_flags) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "tcp_flags", row.tcp_flags);
    }
    for (const tag of parseList(row.tags_json)) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "tag", tag);
    }
    for (const reason of parseList(row.confidence_reasons_json)) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "confidence_reason", reason);
    }
    for (const techniqueId of attackTechniqueIds(techniqueInput)) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "attack_technique", techniqueId);
    }
    if (row.has_username || row.has_password) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "has_credentials", "1");
    }
    if (row.confidence >= 80) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "high_confidence_ip", row.source_ip);
    }

    if (isHttpProtocol(row.protocol) && row.http_path) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "http_path", row.http_path);
      if (row.has_username || row.has_password) {
        await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "http_credential_path", row.http_path);
      }
    }
    if (isHttpProtocol(row.protocol) && row.user_agent) {
      const ua = row.user_agent.length > HTTP_UA_TRUNCATE ? row.user_agent.slice(0, HTTP_UA_TRUNCATE) : row.user_agent;
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "http_user_agent", ua);
    }

    if (NETWORK_KINDS.has(row.event_kind)) {
      await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "net_protocol", row.protocol);
      if (row.destination_port !== null) {
        await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "net_destination_port", String(row.destination_port));
      }
      if (row.tcp_flags) {
        await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "net_tcp_flags", row.tcp_flags);
      }
      if (row.event_kind === "tcp-banner") {
        await updateRollup(db, row.occurred_at, row.source_ip, row.indexed_at, width, "net_banner_ip", row.source_ip);
      }
    }
  }
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

  await indexRollups(db, row);

  await touchIngestWatermark(db, row.occurred_at, row.received_at, row.indexed_at);

  return liveEventFromRow(row);
}
