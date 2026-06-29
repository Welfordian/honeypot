import type { StoredR2Event } from "./types.js";
import { confidenceForEvent } from "@honeypot/shared";

const MAX_TEXT = {
  eventKind: 48,
  trap: 120,
  protocol: 24,
  sensor: 120,
  method: 12,
  path: 1024,
  userAgent: 512,
  payloadPreview: 240,
  tag: 80
};

function text(value: unknown, max: number): string | null {
  if (typeof value !== "string" || !value) return null;
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, (char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`).slice(0, max);
}

function int(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : null;
}

export function safeTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  return tags
    .filter((tag): tag is string => typeof tag === "string")
    .map((tag) => tag.slice(0, MAX_TEXT.tag))
    .slice(0, 32);
}

export function publicPayloadPreview(event: StoredR2Event): string {
  const preview = text(event.payloadMeta?.preview, MAX_TEXT.payloadPreview) ?? "";
  return redactPreview(preview);
}

export function redactPreview(value: string): string {
  let redacted = value.replace(/([A-Za-z0-9_ -]{0,32}(?:password|passwd|secret|token|key)[A-Za-z0-9_ -]{0,32})=([^&\s]+)/gi, "$1=[redacted]");
  const marker = "login attempt [";
  let lower = redacted.toLowerCase();
  let markerIndex = lower.indexOf(marker);

  while (markerIndex >= 0) {
    const valueStart = markerIndex + marker.length;
    const valueEnd = redacted.indexOf("]", valueStart);
    if (valueEnd < 0) break;

    const bracketValue = redacted.slice(valueStart, valueEnd);
    if (bracketValue.includes("/")) {
      redacted = `${redacted.slice(0, valueStart)}[redacted]/[redacted]${redacted.slice(valueEnd)}`;
      lower = redacted.toLowerCase();
      markerIndex = lower.indexOf(marker, valueStart + "[redacted]/[redacted]".length);
    } else {
      markerIndex = lower.indexOf(marker, valueEnd + 1);
    }
  }

  return redacted;
}

export function publicEventRow(event: StoredR2Event, r2Key: string, indexedAt: string) {
  const confidence = confidenceForEvent({
    severity: Math.max(0, Math.min(10, int(event.severity) ?? 1)),
    protocol: text(event.protocol, MAX_TEXT.protocol) ?? "unknown",
    eventKind: text(event.eventKind, MAX_TEXT.eventKind),
    trap: text(event.trap, MAX_TEXT.trap),
    httpPath: text(event.http?.path, MAX_TEXT.path),
    userAgent: text(event.http?.userAgent, MAX_TEXT.userAgent),
    hasCredentials: Boolean(event.credentials?.username || event.credentials?.password || event.credentials?.token),
    hasPayload: Boolean(event.payloadMeta?.sha256 || event.payload?.text || event.payload?.base64),
    isAggregate: Boolean(event.network?.aggregate)
  });

  return {
    id: text(event.eventId, 80) ?? crypto.randomUUID(),
    occurred_at: new Date(event.occurredAt || indexedAt).toISOString(),
    received_at: new Date(event.r2Writer?.acceptedAt || indexedAt).toISOString(),
    event_kind: text(event.eventKind, MAX_TEXT.eventKind) ?? "trap",
    source_ip: text(event.source?.ip, 64) ?? "0.0.0.0",
    source_port: int(event.source?.port),
    destination_port: int(event.destination?.port),
    protocol: text(event.protocol, MAX_TEXT.protocol) ?? "unknown",
    trap: text(event.trap, MAX_TEXT.trap) ?? "unknown",
    sensor_id: text(event.sensorId, MAX_TEXT.sensor) ?? "unknown",
    http_method: text(event.http?.method, MAX_TEXT.method),
    http_path: text(event.http?.path, MAX_TEXT.path),
    http_status: int(event.http?.status),
    user_agent: text(event.http?.userAgent, MAX_TEXT.userAgent),
    credential_kind: text(event.credentials?.kind, 48),
    has_username: event.credentials?.username ? 1 : 0,
    has_password: event.credentials?.password || event.credentials?.token ? 1 : 0,
    payload_sha256: text(event.payloadMeta?.sha256, 64),
    payload_size: int(event.payloadMeta?.sizeBytes) ?? 0,
    payload_preview: publicPayloadPreview(event),
    packet_count: int(event.network?.packetCount) ?? 0,
    byte_count: int(event.network?.byteCount) ?? 0,
    tcp_flags: text(event.network?.tcpFlags, 32),
    is_aggregate: event.network?.aggregate ? 1 : 0,
    pcap_sha256: text(event.network?.pcapSha256, 64),
    pcap_available: event.network?.pcapSha256 ? 1 : 0,
    severity: Math.max(0, Math.min(10, int(event.severity) ?? 1)),
    confidence: confidence.confidence,
    confidence_reasons_json: JSON.stringify(confidence.reasons),
    tags_json: JSON.stringify(safeTags(event.tags)),
    r2_key: r2Key,
    indexed_at: indexedAt
  };
}
