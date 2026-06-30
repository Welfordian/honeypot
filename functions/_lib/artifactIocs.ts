import { parseLimit, parseOffset, urlOf } from "./http";
import type { D1Database } from "@cloudflare/workers-types";

export type ArtifactIocType = "file" | "url" | "domain";

export interface ArtifactIoc {
  type: ArtifactIocType;
  value: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  event_count: number;
  unique_ips: number;
  source_ips?: string[];
  size_bytes?: number;
  mime_guess?: string;
}

export interface PayloadArtifactRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  max_confidence: number;
  unique_ips: number;
  source_ips_csv: string | null;
}

export interface HttpPathArtifactRow {
  http_path: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  event_count: number;
  unique_ips: number;
  source_ips_csv: string | null;
}

export interface ArtifactIocsQuery {
  payloadsSql: string;
  payloadsParams: unknown[];
  pathsSql: string;
  pathsParams: unknown[];
  limit: number;
}

export interface ArtifactIocsQueryOptions {
  defaultLimit?: number;
  maxLimit?: number;
  defaultMinConfidence?: number | null;
}

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;
const PATH_TLD_BLOCKLIST = new Set([
  "php",
  "asp",
  "aspx",
  "jsp",
  "html",
  "htm",
  "js",
  "css",
  "json",
  "xml",
  "txt",
  "cgi",
  "pl",
  "py",
  "rb",
  "sh",
  "exe",
  "dll",
  "bat",
  "cmd"
]);

function isIpAddress(host: string): boolean {
  return IPV4_RE.test(host) || (host.includes(":") && IPV6_RE.test(host));
}

function looksLikeDomain(host: string): boolean {
  const parts = host.split(".");
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1]!.toLowerCase();
  if (tld.length < 2 || !/^[a-z]{2,24}$/.test(tld)) return false;
  if (PATH_TLD_BLOCKLIST.has(tld)) return false;
  return parts.every((part) => part.length > 0);
}

export function extractDomainFromPath(httpPath: string): string | null {
  const trimmed = httpPath.trim();
  if (!trimmed) return null;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const host = new URL(trimmed).hostname;
      if (host && !isIpAddress(host) && looksLikeDomain(host)) return host.toLowerCase();
    } catch {
      /* fall through */
    }
  }

  const protoRelative = /^\/\/([^/?#]+)/.exec(trimmed);
  if (protoRelative?.[1] && !isIpAddress(protoRelative[1]) && looksLikeDomain(protoRelative[1])) {
    return protoRelative[1].toLowerCase();
  }

  const urlInPath = /https?:\/\/([^/?#\s]+)/i.exec(trimmed);
  if (urlInPath?.[1] && !isIpAddress(urlInPath[1]) && looksLikeDomain(urlInPath[1])) {
    return urlInPath[1].toLowerCase();
  }

  const domainSegment =
    /\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?:\/|$|\?)/i.exec(
      trimmed
    );
  if (domainSegment?.[1] && looksLikeDomain(domainSegment[1])) {
    return domainSegment[1].toLowerCase();
  }

  return null;
}

export function extractUriFromEvent(row: {
  http_path: string | null;
}): { type: "url" | "domain"; value: string } | null {
  const httpPath = row.http_path?.trim();
  if (!httpPath) return null;

  if (/^https?:\/\//i.test(httpPath) || /^\/\/[^/]+/.test(httpPath)) {
    return { type: "url", value: httpPath };
  }

  const domain = extractDomainFromPath(httpPath);
  if (domain) return { type: "domain", value: domain };

  if (httpPath.startsWith("/")) {
    return { type: "url", value: httpPath };
  }

  return null;
}

export function artifactFromPayload(row: PayloadArtifactRow): ArtifactIoc {
  const artifact: ArtifactIoc = {
    type: "file",
    value: row.sha256,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    confidence: row.max_confidence,
    event_count: row.event_count,
    unique_ips: row.unique_ips,
    size_bytes: row.size_bytes,
    mime_guess: row.mime_guess
  };
  const sourceIps = parseCsvList(row.source_ips_csv);
  if (sourceIps.length) artifact.source_ips = sourceIps;
  return artifact;
}

export function artifactFromHttpPath(row: HttpPathArtifactRow): ArtifactIoc | null {
  const extracted = extractUriFromEvent(row);
  if (!extracted) return null;

  const artifact: ArtifactIoc = {
    type: extracted.type,
    value: extracted.value,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    confidence: row.confidence,
    event_count: row.event_count,
    unique_ips: row.unique_ips
  };
  const sourceIps = parseCsvList(row.source_ips_csv);
  if (sourceIps.length) artifact.source_ips = sourceIps;
  return artifact;
}

export function buildArtifactIocsQuery(url: URL, options?: ArtifactIocsQueryOptions): ArtifactIocsQuery | Response {
  const limit = parseLimit(url, options?.defaultLimit ?? 100, options?.maxLimit ?? 5000);
  const offset = parseOffset(url);
  const rawMinConfidence = url.searchParams.get("minConfidence");
  const minConfidence =
    rawMinConfidence === null ? (options?.defaultMinConfidence ?? null) : Number(rawMinConfidence);
  const since = url.searchParams.get("since");

  if (
    rawMinConfidence !== null &&
    (minConfidence === null || !Number.isInteger(minConfidence) || minConfidence < 0 || minConfidence > 100)
  ) {
    return new Response("invalid minConfidence", { status: 400 });
  }

  const payloadWhere: string[] = [];
  const payloadParams: unknown[] = [];
  const pathWhere: string[] = ["http_path IS NOT NULL", "http_path != ''"];
  const pathParams: unknown[] = [];

  if (since !== null) {
    const sinceIso = parseSinceParam(since);
    if (sinceIso instanceof Response) return sinceIso;
    payloadWhere.push("p.first_seen >= ?");
    payloadParams.push(sinceIso);
    pathWhere.push("occurred_at >= ?");
    pathParams.push(sinceIso);
  }

  const payloadWhereClause = payloadWhere.length ? `WHERE ${payloadWhere.join(" AND ")}` : "";

  const payloadHaving: string[] = [];
  if (minConfidence !== null) {
    payloadHaving.push("max_confidence >= ?");
    payloadParams.push(minConfidence);
    pathWhere.push("confidence >= ?");
    pathParams.push(minConfidence);
  }

  const pathWhereClause = `WHERE ${pathWhere.join(" AND ")}`;

  const payloadHavingClause = payloadHaving.length ? `HAVING ${payloadHaving.join(" AND ")}` : "";
  payloadParams.push(limit, offset);
  pathParams.push(limit, offset);

  return {
    payloadsSql: `SELECT p.sha256, p.size_bytes, p.mime_guess, p.first_seen, p.last_seen, p.event_count,
       COALESCE(MAX(e.confidence), 0) AS max_confidence,
       COUNT(DISTINCT e.source_ip) AS unique_ips,
       GROUP_CONCAT(DISTINCT e.source_ip) AS source_ips_csv
     FROM payloads p
     LEFT JOIN events e ON e.payload_sha256 = p.sha256
     ${payloadWhereClause}
     GROUP BY p.sha256, p.size_bytes, p.mime_guess, p.first_seen, p.last_seen, p.event_count
     ${payloadHavingClause}
     ORDER BY max_confidence DESC, p.event_count DESC, p.last_seen DESC
     LIMIT ? OFFSET ?`,
    payloadsParams: payloadParams,
    pathsSql: `SELECT http_path, MIN(occurred_at) AS first_seen, MAX(occurred_at) AS last_seen,
       MAX(confidence) AS confidence, COUNT(*) AS event_count,
       COUNT(DISTINCT source_ip) AS unique_ips,
       GROUP_CONCAT(DISTINCT source_ip) AS source_ips_csv
     FROM events
     ${pathWhereClause}
     GROUP BY http_path
     ORDER BY confidence DESC, event_count DESC, last_seen DESC
     LIMIT ? OFFSET ?`,
    pathsParams: pathParams,
    limit
  };
}

function parseSinceParam(value: string): string | Response {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 64 || !Number.isFinite(Date.parse(trimmed))) {
    return new Response("invalid since timestamp", { status: 400 });
  }
  return trimmed;
}

function parseCsvList(value: string | null | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function artifactIocsFromRequest(
  request: Request,
  options?: ArtifactIocsQueryOptions
): ArtifactIocsQuery | Response {
  return buildArtifactIocsQuery(urlOf(request), options);
}

export async function fetchArtifactIocs(
  db: D1Database,
  query: ArtifactIocsQuery
): Promise<ArtifactIoc[]> {
  const [payloadResult, pathResult] = await Promise.all([
    db.prepare(query.payloadsSql).bind(...query.payloadsParams).all<PayloadArtifactRow>(),
    db.prepare(query.pathsSql).bind(...query.pathsParams).all<HttpPathArtifactRow>()
  ]);

  const byKey = new Map<string, ArtifactIoc>();

  for (const row of payloadResult.results) {
    const artifact = artifactFromPayload(row);
    mergeArtifact(byKey, artifact);
  }

  for (const row of pathResult.results) {
    const artifact = artifactFromHttpPath(row);
    if (artifact) mergeArtifact(byKey, artifact);
  }

  return [...byKey.values()]
    .sort((left, right) => {
      if (right.confidence !== left.confidence) return right.confidence - left.confidence;
      if (right.event_count !== left.event_count) return right.event_count - left.event_count;
      return right.last_seen.localeCompare(left.last_seen);
    })
    .slice(0, query.limit);
}

function mergeArtifact(target: Map<string, ArtifactIoc>, artifact: ArtifactIoc): void {
  const key = `${artifact.type}:${artifact.value}`;
  const existing = target.get(key);
  if (!existing) {
    target.set(key, artifact);
    return;
  }

  const mergedSourceIps = mergeUnique(existing.source_ips, artifact.source_ips);
  target.set(key, {
    ...existing,
    first_seen: existing.first_seen < artifact.first_seen ? existing.first_seen : artifact.first_seen,
    last_seen: existing.last_seen > artifact.last_seen ? existing.last_seen : artifact.last_seen,
    confidence: Math.max(existing.confidence, artifact.confidence),
    event_count: existing.event_count + artifact.event_count,
    unique_ips: Math.max(existing.unique_ips, artifact.unique_ips),
    ...(mergedSourceIps.length ? { source_ips: mergedSourceIps } : {})
  });
}

function mergeUnique(left?: string[], right?: string[]): string[] {
  return [...new Set([...(left ?? []), ...(right ?? [])])];
}
