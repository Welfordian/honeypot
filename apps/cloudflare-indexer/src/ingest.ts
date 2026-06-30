import { z } from "zod";
import type { Env, StoredR2Event } from "./types.js";
import { deliverHuntWebhooks } from "./deliverHunts.js";
import { indexStoredEvent } from "./indexEvent.js";
import { publishLiveEvent } from "./live.js";

const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
const DEFAULT_MAX_PAYLOAD_BYTES = 32768;
const MIN_BODY_LIMIT_BYTES = 262144;
const DEFAULT_PCAP_MAX_BYTES = 10 * 1024 * 1024;
const DEFAULT_PCAP_RETENTION_DAYS = 14;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const SOURCE_IP_SCHEMA = z
  .string()
  .min(3)
  .max(64)
  .regex(/^[0-9a-fA-F:.]+$/);

const EVENT_SCHEMA = z.object({
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
  destination: z
    .object({
      port: z.number().int().min(0).max(65535).optional()
    })
    .optional(),
  http: z
    .object({
      method: z.string().max(12).optional(),
      path: z.string().max(4096).optional(),
      status: z.number().int().min(100).max(599).optional(),
      headers: z.record(z.string(), z.union([z.string(), z.array(z.string())])).optional(),
      query: z.record(z.string(), z.union([z.string(), z.array(z.string())])).optional(),
      userAgent: z.string().max(1024).optional()
    })
    .optional(),
  credentials: z
    .object({
      username: z.string().max(512).optional(),
      password: z.string().max(512).optional(),
      token: z.string().max(2048).optional(),
      kind: z.string().max(48).optional()
    })
    .optional(),
  payload: z
    .object({
      text: z.string().max(65536).optional(),
      base64: z.string().max(131072).optional(),
      mimeGuess: z.string().max(120).optional()
    })
    .optional(),
  network: z
    .object({
      packetCount: z.number().int().min(0).max(1_000_000).optional(),
      byteCount: z.number().int().min(0).max(1_000_000_000).optional(),
      tcpFlags: z.string().max(32).optional(),
      aggregate: z.boolean().optional(),
      pcapSha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
      interfaceName: z.string().max(32).optional()
    })
    .optional(),
  tags: z.array(z.string().min(1).max(80)).max(32).optional(),
  severity: z.number().int().min(0).max(10).optional(),
  raw: z.record(z.string(), z.unknown()).optional()
});

type ParsedEvent = z.infer<typeof EVENT_SCHEMA>;

class IngestError extends Error {
  constructor(
    readonly code: string,
    readonly status: number
  ) {
    super(code);
  }
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store"
    }
  });
}

function maxPayloadBytes(env: Env): number {
  const parsed = Number(env.MAX_PAYLOAD_BYTES);
  if (Number.isInteger(parsed) && parsed >= 1024 && parsed <= 1024 * 1024) return parsed;
  return DEFAULT_MAX_PAYLOAD_BYTES;
}

function maxBodyBytes(payloadLimit: number): number {
  return Math.max(MIN_BODY_LIMIT_BYTES, payloadLimit * 4 + 65536);
}

function pcapMaxBytes(env: Env): number {
  const parsed = Number(env.PCAP_MAX_BYTES);
  if (Number.isInteger(parsed) && parsed >= 1024 * 1024 && parsed <= 50 * 1024 * 1024) return parsed;
  return DEFAULT_PCAP_MAX_BYTES;
}

function pcapRetentionDays(env: Env): number {
  const parsed = Number(env.PCAP_RETENTION_DAYS);
  if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 90) return parsed;
  return DEFAULT_PCAP_RETENTION_DAYS;
}

async function readLimitedBytes(request: Request, limit: number): Promise<Uint8Array> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > limit) throw new IngestError("body_too_large", 413);
  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new IngestError("body_too_large", 413);
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[a-f0-9]{64}$/i.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function hmacSha256(secret: string, timestamp: string, rawBody: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prefix = textEncoder.encode(`${timestamp}.`);
  const signed = new Uint8Array(prefix.byteLength + rawBody.byteLength);
  signed.set(prefix, 0);
  signed.set(rawBody, prefix.byteLength);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, toArrayBuffer(signed)));
}

async function verifySignature(env: Env, request: Request, rawBody: Uint8Array): Promise<void> {
  if (!env.INGEST_HMAC_SECRET) throw new IngestError("ingest_not_configured", 503);

  const timestamp = request.headers.get("x-hp-timestamp") ?? "";
  const signature = request.headers.get("x-hp-signature") ?? "";
  const parsedTimestamp = Date.parse(timestamp);
  if (!timestamp || !signature) throw new IngestError("missing_signature", 401);
  if (!Number.isFinite(parsedTimestamp)) throw new IngestError("invalid_timestamp", 401);
  if (Math.abs(Date.now() - parsedTimestamp) > MAX_CLOCK_SKEW_MS) throw new IngestError("timestamp_outside_window", 401);

  const provided = hexToBytes(signature);
  if (!provided) throw new IngestError("invalid_signature", 401);

  const expected = await hmacSha256(env.INGEST_HMAC_SECRET, timestamp, rawBody);
  const timingSafeSubtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual(a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView): boolean;
  };
  if (
    !timingSafeSubtle.timingSafeEqual(
      toArrayBuffer(expected),
      toArrayBuffer(provided)
    )
  ) {
    throw new IngestError("invalid_signature", 401);
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

function suppressedSourceIps(env: Env): Set<string> {
  return new Set(
    (env.SUPPRESSED_SOURCE_IPS ?? "")
      .split(",")
      .map((ip) => normalizeIp(ip.trim()))
      .filter(Boolean)
  );
}

function sourceIpFromRaw(raw: unknown): string | null {
  if (!raw || typeof raw !== "object") return null;
  const source = (raw as { source?: { ip?: unknown } }).source;
  return typeof source?.ip === "string" ? normalizeIp(source.ip) : null;
}

function parseSourceIps(value: string | null): string[] {
  if (!value) return [];
  return Array.from(
    new Set(
      value
        .split(",")
        .map((ip) => normalizeIp(ip.trim()))
        .filter((ip) => SOURCE_IP_SCHEMA.safeParse(ip).success)
    )
  ).sort();
}

function safePreview(value: string, maxChars: number): string {
  const clipped = value.length > maxChars ? `${value.slice(0, maxChars)}...[truncated:${value.length}]` : value;
  return clipped.replaceAll("\u0000", "\\0");
}

function bytesFromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function scoreEvent(event: ParsedEvent): number {
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

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

export function objectKey(prefix: string, event: StoredR2Event): string {
  const date = new Date(event.occurredAt);
  const yyyy = date.getUTCFullYear();
  const mm = pad(date.getUTCMonth() + 1);
  const dd = pad(date.getUTCDate());
  const hh = pad(date.getUTCHours());
  return `${prefix.replace(/^\/+|\/+$/g, "")}/${yyyy}/${mm}/${dd}/${hh}/${event.eventId}.json`;
}

export async function normalizeForR2(raw: unknown, payloadLimit: number): Promise<StoredR2Event> {
  const parsed = EVENT_SCHEMA.parse(raw);
  const payloadBytes = parsed.payload?.text
    ? textEncoder.encode(parsed.payload.text)
    : parsed.payload?.base64
      ? bytesFromBase64(parsed.payload.base64)
      : null;
  const clippedPayload = payloadBytes?.subarray(0, payloadLimit) ?? null;
  const decodedPreview = clippedPayload ? textDecoder.decode(clippedPayload) : "";

  const source: StoredR2Event["source"] = { ip: normalizeIp(parsed.source.ip) };
  if (parsed.source.port !== undefined) source.port = parsed.source.port;

  const event: StoredR2Event = {
    eventId: parsed.eventId ?? crypto.randomUUID(),
    occurredAt: parsed.occurredAt ?? new Date().toISOString(),
    eventKind: parsed.eventKind ?? "trap",
    sensorId: parsed.sensorId,
    trap: parsed.trap,
    protocol: parsed.protocol,
    source,
    severity: scoreEvent(parsed),
    r2Writer: {
      acceptedAt: new Date().toISOString(),
      schemaVersion: 1
    }
  };

  if (parsed.destination) event.destination = parsed.destination;
  if (parsed.http) event.http = parsed.http;
  if (parsed.credentials) event.credentials = parsed.credentials;
  if (parsed.network) event.network = parsed.network;
  if (parsed.tags) event.tags = parsed.tags;
  if (parsed.raw) event.raw = parsed.raw;

  if (clippedPayload) {
    event.payload = parsed.payload?.base64
      ? { ...parsed.payload, base64: bytesToBase64(clippedPayload) }
      : { ...parsed.payload, text: safePreview(decodedPreview, payloadLimit) };
    event.payloadMeta = {
      sha256: await sha256Hex(clippedPayload),
      sizeBytes: clippedPayload.byteLength,
      mimeGuess: parsed.payload?.mimeGuess ?? "application/octet-stream",
      preview: safePreview(decodedPreview, 240)
    };
  }

  return event;
}

function requiredHeader(request: Request, name: string): string {
  const value = request.headers.get(name)?.trim();
  if (!value) throw new IngestError(`missing_${name.toLowerCase().replaceAll("-", "_")}`, 400);
  return value;
}

function isoHeader(request: Request, name: string): string {
  const value = requiredHeader(request, name);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new IngestError(`invalid_${name.toLowerCase().replaceAll("-", "_")}`, 400);
  return new Date(parsed).toISOString();
}

function optionalIntegerHeader(request: Request, name: string): number {
  const value = request.headers.get(name);
  if (!value) return 0;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) throw new IngestError(`invalid_${name.toLowerCase().replaceAll("-", "_")}`, 400);
  return parsed;
}

function pcapObjectKey(prefix: string, captureId: string, firstSeen: string): string {
  const date = new Date(firstSeen);
  const yyyy = date.getUTCFullYear();
  const mm = pad(date.getUTCMonth() + 1);
  const dd = pad(date.getUTCDate());
  const hh = pad(date.getUTCHours());
  return `${prefix.replace(/^\/+|\/+$/g, "")}/${yyyy}/${mm}/${dd}/${hh}/${captureId}.pcap.gz`;
}

export async function handlePcapIngest(request: Request, env: Env): Promise<Response> {
  try {
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    const rawBody = await readLimitedBytes(request, pcapMaxBytes(env));
    await verifySignature(env, request, rawBody);

    const sourceIps = parseSourceIps(request.headers.get("x-hp-source-ips"));
    const suppressed = suppressedSourceIps(env);
    if (sourceIps.some((ip) => suppressed.has(ip))) return json({ accepted: true, suppressed: true }, 202);

    const captureId = requiredHeader(request, "x-hp-capture-id");
    if (!/^[A-Za-z0-9_.:-]{1,120}$/.test(captureId)) throw new IngestError("invalid_capture_id", 400);
    const firstSeen = isoHeader(request, "x-hp-first-seen");
    const lastSeen = isoHeader(request, "x-hp-last-seen");
    const interfaceName = requiredHeader(request, "x-hp-interface").slice(0, 32);
    const expectedSha256 = requiredHeader(request, "x-hp-sha256").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new IngestError("invalid_sha256", 400);
    const actualSha256 = await sha256Hex(rawBody);
    if (actualSha256 !== expectedSha256) throw new IngestError("sha256_mismatch", 400);

    const uploadedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + pcapRetentionDays(env) * 24 * 60 * 60 * 1000).toISOString();
    const packetCount = optionalIntegerHeader(request, "x-hp-packet-count");
    const key = pcapObjectKey(env.PCAP_PREFIX ?? "private-pcap", captureId, firstSeen);

    await env.EVENTS_BUCKET.put(key, rawBody, {
      httpMetadata: {
        contentType: "application/gzip",
        cacheControl: "private, no-store"
      },
      customMetadata: {
        captureId,
        sha256: actualSha256,
        sourceIps: sourceIps.join(","),
        expiresAt
      }
    });

    await env.DB.prepare(
      `INSERT INTO pcap_chunks (
        capture_id, first_seen, last_seen, interface_name, sha256, size_bytes, packet_count,
        source_ips_json, r2_key, expires_at, uploaded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(capture_id) DO UPDATE SET
        last_seen = excluded.last_seen,
        sha256 = excluded.sha256,
        size_bytes = excluded.size_bytes,
        packet_count = excluded.packet_count,
        source_ips_json = excluded.source_ips_json,
        r2_key = excluded.r2_key,
        expires_at = excluded.expires_at,
        uploaded_at = excluded.uploaded_at`
    )
      .bind(
        captureId,
        firstSeen,
        lastSeen,
        interfaceName,
        actualSha256,
        rawBody.byteLength,
        packetCount,
        JSON.stringify(sourceIps),
        key,
        expiresAt,
        uploadedAt
      )
      .run();

    return json({ accepted: true, capture_id: captureId, sha256: actualSha256 }, 202);
  } catch (error) {
    if (error instanceof IngestError) return json({ error: error.code }, error.status);
    console.error("pcap ingest failed", error);
    return json({ error: "pcap_ingest_failed" }, 500);
  }
}

export async function handleIngest(request: Request, env: Env): Promise<Response> {
  try {
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    const payloadLimit = maxPayloadBytes(env);
    const rawBody = await readLimitedBytes(request, maxBodyBytes(payloadLimit));
    await verifySignature(env, request, rawBody);

    const rawText = textDecoder.decode(rawBody);
    const rawEvent = JSON.parse(rawText) as unknown;
    const sourceIp = sourceIpFromRaw(rawEvent);
    if (sourceIp && suppressedSourceIps(env).has(sourceIp)) return json({ accepted: true, suppressed: true }, 202);

    const stored = await normalizeForR2(rawEvent, payloadLimit);
    const key = objectKey(env.R2_PREFIX ?? "raw", stored);

    await env.EVENTS_BUCKET.put(key, `${JSON.stringify(stored)}\n`, {
      httpMetadata: {
        contentType: "application/json",
        cacheControl: "no-store"
      }
    });

    try {
      const indexed = await indexStoredEvent(env.DB, stored, key, env.EVENTS_BUCKET);
      if (indexed) {
        await publishLiveEvent(env, indexed);
        try {
          await deliverHuntWebhooks(env);
        } catch (error) {
          console.error("hunt webhook delivery failed", error);
        }
      }
    } catch (error) {
      console.error("direct D1 index failed; queue notification will retry", { key, error });
    }

    return json({ accepted: true, key }, 202);
  } catch (error) {
    if (error instanceof IngestError) return json({ error: error.code }, error.status);
    if (error instanceof SyntaxError || error instanceof z.ZodError) return json({ error: "invalid_event" }, 400);
    console.error("ingest failed", error);
    return json({ error: "ingest_failed" }, 500);
  }
}
