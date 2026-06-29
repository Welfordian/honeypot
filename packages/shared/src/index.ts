import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

export const SOURCE_IP_SCHEMA = z
  .string()
  .min(3)
  .max(64)
  .regex(/^[0-9a-fA-F:.]+$/);

export const HONEYPOT_EVENT_SCHEMA = z.object({
  eventId: z.string().uuid().optional(),
  occurredAt: z.string().datetime().optional(),
  eventKind: z.string().min(1).max(48).optional(),
  sensorId: z.string().min(1).max(120),
  trap: z.string().min(1).max(120),
  protocol: z.string().min(1).max(24),
  source: z.object({
    ip: SOURCE_IP_SCHEMA,
    port: z.number().int().min(0).max(65535).optional()
  }),
  destination: z.object({
    port: z.number().int().min(0).max(65535).optional()
  }).optional(),
  http: z.object({
    method: z.string().max(12).optional(),
    path: z.string().max(4096).optional(),
    status: z.number().int().min(100).max(599).optional(),
    headers: z.record(z.string(), z.union([z.string(), z.array(z.string())])).optional(),
    query: z.record(z.string(), z.union([z.string(), z.array(z.string())])).optional(),
    userAgent: z.string().max(1024).optional()
  }).optional(),
  credentials: z.object({
    username: z.string().max(512).optional(),
    password: z.string().max(512).optional(),
    token: z.string().max(2048).optional(),
    kind: z.string().max(48).optional()
  }).optional(),
  payload: z.object({
    text: z.string().max(65536).optional(),
    base64: z.string().max(131072).optional(),
    mimeGuess: z.string().max(120).optional()
  }).optional(),
  network: z.object({
    packetCount: z.number().int().min(0).max(1_000_000).optional(),
    byteCount: z.number().int().min(0).max(1_000_000_000).optional(),
    tcpFlags: z.string().max(32).optional(),
    aggregate: z.boolean().optional(),
    pcapSha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    interfaceName: z.string().max(32).optional()
  }).optional(),
  tags: z.array(z.string().min(1).max(80)).max(32).optional(),
  severity: z.number().int().min(0).max(10).optional(),
  raw: z.record(z.string(), z.unknown()).optional()
});

export type HoneypotEvent = z.infer<typeof HONEYPOT_EVENT_SCHEMA>;

export const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "proxy-authorization"
]);

export function normalizeIp(ip: string): string {
  if (ip.startsWith("::ffff:")) return ip.slice(7);
  return ip;
}

export function redacted(value: unknown, visible = 4): string {
  if (typeof value !== "string") return "[redacted]";
  if (value.length <= visible) return "[redacted]";
  return `${value.slice(0, visible)}...[redacted:${value.length}]`;
}

export function redactHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    result[key] = SENSITIVE_HEADER_NAMES.has(key.toLowerCase()) ? redacted(Array.isArray(value) ? value.join(";") : value) : value;
  }
  return result;
}

export function safePreview(value: string, maxChars = 2048): string {
  const clipped = value.length > maxChars ? `${value.slice(0, maxChars)}...[truncated:${value.length}]` : value;
  return clipped.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, (char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

export function guessMimeFromText(text: string): string {
  const trimmed = text.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "application/json";
  if (trimmed.startsWith("<")) return "text/html";
  if (/^[A-Za-z0-9+/=\r\n]+$/.test(trimmed) && trimmed.length > 80) return "text/plain";
  return "text/plain";
}

export function scoreEvent(event: HoneypotEvent): number {
  let score = event.severity ?? 1;
  const path = event.http?.path?.toLowerCase() ?? "";
  const protocol = event.protocol.toLowerCase();
  const eventKind = event.eventKind?.toLowerCase() ?? "";

  if (event.credentials) score += 4;
  if (event.payload?.text || event.payload?.base64) score += 2;
  if (["ssh", "telnet", "mysql", "mssql", "redis", "smb", "rdp"].includes(protocol)) score += 2;
  if (/(wp-login|phpmyadmin|\.env|\.git|metadata|jenkins|grafana|kubernetes|docker|laravel|actuator)/.test(path)) score += 2;
  if (/(curl|wget|python-requests|masscan|zgrab|nmap|sqlmap|nikto)/i.test(event.http?.userAgent ?? "")) score += 1;
  if (eventKind === "tcp-banner") score += 1;
  if (event.network?.aggregate) score += 1;

  return Math.max(0, Math.min(10, score));
}

export interface ConfidenceEventInput {
  severity: number;
  protocol: string;
  eventKind?: string | null;
  trap?: string | null;
  httpPath?: string | null;
  userAgent?: string | null;
  hasCredentials?: boolean;
  hasPayload?: boolean;
  isAggregate?: boolean;
}

export interface ConfidenceProfileInput {
  maxEventConfidence: number;
  eventCount: number;
  uniqueTraps: string[];
  protocols: string[];
  eventReasons?: string[];
}

export interface ConfidenceResult {
  confidence: number;
  reasons: string[];
}

const HIGH_RISK_PROTOCOLS = new Set(["ssh", "telnet", "mysql", "mssql", "redis", "smb", "rdp", "vnc", "ftp"]);
const SENSITIVE_PATH_PATTERN = /(wp-login|wp-admin|phpmyadmin|\.env|\.git|metadata|jenkins|grafana|kubernetes|docker|laravel|actuator|config|backup|admin|login)/i;
const EXPLOIT_PATH_PATTERN = /(\.\.\/|%2e%2e|cgi-bin|eval\(|base64_decode|select.+from|union.+select|cmd=|exec=|shell|jndi:|struts|thinkphp|boaform|vendor\/phpunit)/i;
const SCANNER_UA_PATTERN = /(curl|wget|python-requests|masscan|zgrab|nmap|sqlmap|nikto|go-http-client|internetmeasurement|censys|shodan|scanner)/i;

function boundedConfidence(value: number): number {
  return Math.max(0, Math.min(100, Math.trunc(value)));
}

function uniqueReasons(reasons: string[]): string[] {
  return Array.from(new Set(reasons)).sort();
}

export function confidenceForEvent(input: ConfidenceEventInput): ConfidenceResult {
  const protocol = input.protocol.toLowerCase();
  const eventKind = input.eventKind?.toLowerCase() ?? "";
  const path = input.httpPath ?? "";
  const userAgent = input.userAgent ?? "";
  const reasons: string[] = [];
  let confidence = Math.max(0, Math.min(10, Math.trunc(input.severity))) * 6;

  if (input.severity >= 8) reasons.push("high_severity");
  else if (input.severity >= 5) reasons.push("medium_severity");

  if (input.hasCredentials) {
    confidence += 22;
    reasons.push("credential_attempt");
  }

  if (input.hasPayload) {
    confidence += 14;
    reasons.push("payload_present");
  }

  if (HIGH_RISK_PROTOCOLS.has(protocol)) {
    confidence += 14;
    reasons.push("high_risk_protocol");
  }

  if (SENSITIVE_PATH_PATTERN.test(path)) {
    confidence += 14;
    reasons.push("sensitive_path");
  }

  if (EXPLOIT_PATH_PATTERN.test(path)) {
    confidence += 16;
    reasons.push("exploit_path");
  }

  if (SCANNER_UA_PATTERN.test(userAgent)) {
    confidence += 8;
    reasons.push("scanner_user_agent");
  }

  if (eventKind === "network-attempt") {
    confidence += 8;
    reasons.push("network_attempt");
  }

  if (eventKind === "tcp-banner") {
    confidence += 12;
    reasons.push("unknown_port_banner");
  }

  if (input.isAggregate) {
    confidence += 10;
    reasons.push("repeat_activity");
  }

  return {
    confidence: boundedConfidence(confidence),
    reasons: uniqueReasons(reasons)
  };
}

export function confidenceForProfile(input: ConfidenceProfileInput): ConfidenceResult {
  const reasons = [...(input.eventReasons ?? [])];
  let confidence = boundedConfidence(input.maxEventConfidence);

  if (input.eventCount >= 20) {
    confidence += 14;
    reasons.push("repeat_activity");
  } else if (input.eventCount >= 5) {
    confidence += 8;
    reasons.push("repeat_activity");
  }

  if (input.uniqueTraps.length >= 4) {
    confidence += 14;
    reasons.push("trap_diversity");
  } else if (input.uniqueTraps.length >= 2) {
    confidence += 8;
    reasons.push("trap_diversity");
  }

  if (input.protocols.length >= 3) {
    confidence += 10;
    reasons.push("protocol_diversity");
  } else if (input.protocols.length >= 2) {
    confidence += 6;
    reasons.push("protocol_diversity");
  }

  return {
    confidence: boundedConfidence(confidence),
    reasons: uniqueReasons(reasons)
  };
}

export function signBody(secret: string, timestamp: string, rawBody: string | Buffer): string {
  return createHmac("sha256", secret).update(timestamp).update(".").update(rawBody).digest("hex");
}

export function verifySignature(secret: string, timestamp: string, rawBody: string | Buffer, provided: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(provided)) return false;
  const expected = signBody(secret, timestamp, rawBody);
  return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(provided, "hex"));
}

export function parseForwardedIp(value: string | string[] | undefined): string | undefined {
  const first = Array.isArray(value) ? value[0] : value;
  if (!first) return undefined;
  return normalizeIp(first.split(",")[0]?.trim() ?? "");
}
