export interface EventRow {
  id: string;
  occurred_at: string;
  received_at: string;
  event_kind: string;
  source_ip: string;
  source_port?: number | null;
  destination_port?: number | null;
  protocol: string;
  trap: string;
  sensor_id: string;
  http_method?: string | null;
  http_path?: string | null;
  http_status?: number | null;
  user_agent?: string | null;
  credential_kind?: string | null;
  has_credentials: boolean;
  payload_sha256?: string | null;
  payload_size?: number;
  payload_preview?: string;
  packet_count: number;
  byte_count: number;
  tcp_flags?: string | null;
  is_aggregate: boolean;
  pcap_sha256?: string | null;
  pcap_available: boolean;
  severity: number;
  confidence: number;
  confidence_reasons: string[];
  tags: string[];
}

export interface IpProfile {
  source_ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  unique_traps: string[];
  protocols: string[];
  score: number;
  confidence: number;
  confidence_reasons: string[];
  last_trap?: string | null;
  last_protocol?: string | null;
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}

export interface Overview {
  totals: { events: number; unique_ips: number; max_severity: number };
  timeline: Array<{ bucket: string; count: number }>;
  topIps: Array<{ key: string; count: number; max_severity: number }>;
  topProtocols: Array<{ key: string; count: number }>;
  topTraps: Array<{ key: string; count: number }>;
  topSeverities: Array<{ key: string | number; count: number }>;
  sensors: Array<{
    sensor_id: string;
    last_seen: string;
    last_protocol: string;
    last_trap: string;
    event_count: number;
  }>;
}

export interface PayloadRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  preview: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  max_confidence: number;
  unique_ips: number;
}

export interface TimelinePoint {
  bucket: string;
  count: number;
  unique_ips?: number;
  max_severity?: number;
  max_confidence?: number;
}

export interface RelatedIp {
  source_ip: string;
  event_count: number;
  max_confidence: number;
  last_seen: string;
}

export interface DimensionCount {
  key: string;
  count: number;
}

export interface NetworkOverview {
  totals: {
    events: number;
    unique_ips: number;
    packets: number;
    bytes: number;
    aggregate_events: number;
  };
  timeline: Array<{ bucket: string; count: number; unique_ips: number }>;
  topPorts: DimensionCount[];
  topProtocols: DimensionCount[];
  tcpFlags: DimensionCount[];
  eventKinds: DimensionCount[];
  topBannerIps: DimensionCount[];
  pcap: {
    chunks: number;
    bytes: number;
    packets: number;
  };
}

export interface PayloadDetail {
  payload: PayloadRow;
  related_ips: RelatedIp[];
  protocols: DimensionCount[];
  traps: DimensionCount[];
  events: EventRow[];
  next_cursor: string | null;
}

export interface IpDetail {
  profile: IpProfile;
  events: EventRow[];
  next_cursor: string | null;
}

export type LiveStatus = "connecting" | "live" | "reconnecting" | "offline";

export const LIVE_STATUS_LABELS: Record<LiveStatus, string> = {
  connecting: "Connecting to Durable Object stream",
  live: "Durable Object stream",
  reconnecting: "Reconnecting stream",
  offline: "Stream offline"
};

export interface EventFilters {
  ip: string;
  eventType: string;
  eventKind: string;
  destinationPort: string;
  aggregate: string;
  sinceHours: string;
  tag: string;
  confidenceReason: string;
  minConfidence: string;
  hasCredentials: string;
  payloadHash: string;
  trap: string;
  userAgent: string;
}

export const CONFIDENCE_REASONS = [
  "high_severity",
  "medium_severity",
  "credential_attempt",
  "payload_present",
  "high_risk_protocol",
  "sensitive_path",
  "exploit_path",
  "scanner_user_agent",
  "network_attempt",
  "unknown_port_banner",
  "repeat_activity",
  "trap_diversity",
  "protocol_diversity"
] as const;

export const DEFAULT_EVENT_FILTERS: EventFilters = {
  ip: "",
  eventType: "",
  eventKind: "",
  destinationPort: "",
  aggregate: "",
  sinceHours: "24",
  tag: "",
  confidenceReason: "",
  minConfidence: "",
  hasCredentials: "",
  payloadHash: "",
  trap: "",
  userAgent: ""
};

export type SensorStatus = "ok" | "warning" | "stale";

export interface IntelAttacker {
  key: string;
  count: number;
  max_severity: number;
  max_confidence: number;
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}

export interface IntelCampaign {
  sha256: string;
  event_count: number;
  unique_ips: number;
  max_confidence: number;
}

export interface IntelOverview {
  topAttackers: IntelAttacker[];
  topConfidenceReasons: DimensionCount[];
  topTags: DimensionCount[];
  credentialAttempts: number;
  highConfidenceIps: number;
  campaigns: IntelCampaign[];
}

export interface HttpIntelRow {
  key: string;
  count: number;
  unique_ips: number;
}

export interface HttpProbeTrend {
  key: string;
  timeline: Array<{ bucket: string; count: number }>;
}

export interface HttpIntelOverview {
  topPaths: HttpIntelRow[];
  topUserAgents: HttpIntelRow[];
  probeTrends: HttpProbeTrend[];
  credentialPaths: HttpIntelRow[];
}

export interface IntelActor {
  actor_id: string;
  source_ip: string;
  event_count: number;
  confidence: number;
  first_seen: string;
  last_seen: string;
  trap_sequence: string[];
  protocols: string[];
  tags: string[];
  related_payloads: string[];
  related_ips: string[];
}

export interface BehavioralCampaign {
  campaign_id: string;
  traps: string[];
  unique_ips: number;
  event_count: number;
  max_confidence: number;
  source_ips: string[];
}

export interface IntelCampaigns {
  payload_campaigns: IntelCampaign[];
  behavioral_campaigns: BehavioralCampaign[];
}

export interface OpsSensor {
  sensor_id: string;
  last_seen: string;
  last_protocol: string;
  last_trap: string;
  event_count: number;
  status: SensorStatus;
}

export interface OpsStatus {
  sensors: OpsSensor[];
  ingest: {
    last_event_at: string | null;
    last_received_at: string | null;
  };
  capture: {
    chunks_24h: number;
    packets_24h: number;
    bytes_24h: number;
    expiring_soon: number;
  };
  totals24h: {
    events: number;
    unique_ips: number;
  };
}

export interface RollupPoint {
  bucket: string;
  count: number;
  unique_ips: number;
}

export interface RollupSeries {
  key: string;
  points: RollupPoint[];
}

export interface RollupsResponse {
  dimension: string;
  bucketWidth: "hour" | "day";
  sinceHours: number;
  series: RollupSeries[];
}

export interface CompareWindow {
  hours: number;
  count: number;
}

export interface CompareResponse {
  dimension: "tag" | "confidenceReason" | "trap";
  key: string;
  windowA: CompareWindow;
  windowB: CompareWindow;
}

export interface NewIpsResponse {
  since: string;
  count: number;
  ips: IpProfile[];
}
