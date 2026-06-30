import { attackTechniqueIds } from "./attackMapping";
import { redactPreview } from "./redaction";

export interface EventRow {
  id: string;
  occurred_at: string;
  received_at: string;
  event_kind: string;
  source_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  trap: string;
  sensor_id: string;
  http_method: string | null;
  http_path: string | null;
  http_status: number | null;
  user_agent: string | null;
  credential_kind: string | null;
  has_username: number;
  has_password: number;
  payload_sha256: string | null;
  payload_size: number;
  payload_preview: string;
  packet_count: number;
  byte_count: number;
  tcp_flags: string | null;
  is_aggregate: number;
  pcap_sha256: string | null;
  pcap_available: number;
  severity: number;
  confidence: number;
  confidence_reasons_json: string;
  tags_json: string;
}

export function tags(row: { tags_json?: string | null }): string[] {
  try {
    const parsed = JSON.parse(row.tags_json ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

export function publicEvent(row: EventRow) {
  const confidence_reasons = parseJsonList(row.confidence_reasons_json);
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
    payload_preview: redactPreview(row.payload_preview),
    packet_count: row.packet_count,
    byte_count: row.byte_count,
    tcp_flags: row.tcp_flags,
    is_aggregate: Boolean(row.is_aggregate),
    pcap_sha256: row.pcap_sha256,
    pcap_available: Boolean(row.pcap_available),
    severity: row.severity,
    confidence: row.confidence,
    confidence_reasons,
    attack_techniques: attackTechniqueIds({
      protocol: row.protocol,
      trap: row.trap,
      http_path: row.http_path,
      has_credentials: Boolean(row.has_username || row.has_password),
      confidence_reasons
    }),
    tags: tags(row)
  };
}

export function eventCursor(row: Pick<EventRow, "occurred_at" | "id">): string {
  return `${row.occurred_at}|${row.id}`;
}

export function publicEventPage(rows: EventRow[], limit: number) {
  const pageRows = rows.slice(0, limit);
  const last = pageRows[pageRows.length - 1];
  return {
    events: pageRows.map(publicEvent),
    next_cursor: rows.length > limit && last ? eventCursor(last) : null
  };
}

export function parseJsonList(value: string | null): string[] {
  try {
    const parsed = JSON.parse(value ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}
