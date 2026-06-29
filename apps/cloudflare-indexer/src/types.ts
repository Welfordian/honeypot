export interface Env {
  EVENTS_BUCKET: R2Bucket;
  DB: D1Database;
  LIVE_STREAM?: Fetcher;
  INDEXER_ADMIN_TOKEN?: string;
  INGEST_HMAC_SECRET?: string;
  R2_PREFIX?: string;
  PCAP_PREFIX?: string;
  PCAP_MAX_BYTES?: string;
  PCAP_RETENTION_DAYS?: string;
  MAX_PAYLOAD_BYTES?: string;
  SUPPRESSED_SOURCE_IPS?: string;
}

export interface LiveEvent {
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
  has_credentials: boolean;
  payload_sha256: string | null;
  payload_size: number;
  payload_preview: string;
  packet_count: number;
  byte_count: number;
  tcp_flags: string | null;
  is_aggregate: boolean;
  pcap_sha256: string | null;
  pcap_available: boolean;
  severity: number;
  confidence: number;
  confidence_reasons: string[];
  tags: string[];
}

export interface StoredR2Event {
  eventId: string;
  occurredAt: string;
  eventKind?: string | undefined;
  sensorId: string;
  trap: string;
  protocol: string;
  source: {
    ip: string;
    port?: number | undefined;
  };
  destination?: {
    port?: number | undefined;
  };
  http?: {
    method?: string | undefined;
    path?: string | undefined;
    status?: number | undefined;
    userAgent?: string | undefined;
    headers?: Record<string, string | string[]> | undefined;
    query?: Record<string, string | string[]> | undefined;
  };
  credentials?: {
    kind?: string | undefined;
    username?: string | undefined;
    password?: string | undefined;
    token?: string | undefined;
  };
  payload?: {
    text?: string | undefined;
    base64?: string | undefined;
    mimeGuess?: string | undefined;
  };
  payloadMeta?: {
    sha256: string;
    sizeBytes: number;
    mimeGuess: string;
    preview: string;
  };
  network?: {
    packetCount?: number | undefined;
    byteCount?: number | undefined;
    tcpFlags?: string | undefined;
    aggregate?: boolean | undefined;
    pcapSha256?: string | undefined;
    interfaceName?: string | undefined;
  };
  severity: number;
  tags?: string[];
  raw?: Record<string, unknown>;
  r2Writer?: {
    acceptedAt?: string | undefined;
    schemaVersion?: number | undefined;
  };
}

export interface R2NotificationBody {
  bucket?: string;
  object?: {
    key?: string;
    name?: string;
  };
  key?: string;
}
