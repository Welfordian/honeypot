import { parseLimit, parseOffset, urlOf } from "./http";
import { parseJsonList } from "./rows";

export interface IpProfileRow {
  source_ip: string;
  first_seen: string;
  last_seen: string;
  score: number;
  confidence: number;
  confidence_reasons_json: string;
  unique_traps_json: string;
  protocols_json: string;
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}

export interface IpIoc {
  source_ip: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  score: number;
  confidence_reasons: string[];
  unique_traps: string[];
  protocols: string[];
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}

export interface IpIocsQuery {
  sql: string;
  params: unknown[];
  limit: number;
}

export interface IpIocsQueryOptions {
  defaultLimit?: number;
  maxLimit?: number;
  defaultMinConfidence?: number | null;
}

export function publicIpIoc(row: IpProfileRow): IpIoc {
  const ioc: IpIoc = {
    source_ip: row.source_ip,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    confidence: row.confidence,
    score: row.score,
    confidence_reasons: parseJsonList(row.confidence_reasons_json),
    unique_traps: parseJsonList(row.unique_traps_json),
    protocols: parseJsonList(row.protocols_json)
  };

  if (row.country_code != null) ioc.country_code = row.country_code;
  if (row.asn != null) ioc.asn = row.asn;
  if (row.as_name != null) ioc.as_name = row.as_name;

  return ioc;
}

export function buildIpIocsQuery(url: URL, options?: IpIocsQueryOptions): IpIocsQuery | Response {
  const limit = parseLimit(url, options?.defaultLimit ?? 100, options?.maxLimit ?? 5000);
  const offset = parseOffset(url);
  const rawMinConfidence = url.searchParams.get("minConfidence");
  const minConfidence =
    rawMinConfidence === null
      ? (options?.defaultMinConfidence ?? null)
      : Number(rawMinConfidence);
  const since = url.searchParams.get("since");
  const where: string[] = [];
  const params: unknown[] = [];

  if (rawMinConfidence !== null && (minConfidence === null || !Number.isInteger(minConfidence) || minConfidence < 0 || minConfidence > 100)) {
    return new Response("invalid minConfidence", { status: 400 });
  }
  if (since !== null) {
    const sinceIso = parseSinceParam(since);
    if (sinceIso instanceof Response) return sinceIso;
    where.push("first_seen >= ?");
    params.push(sinceIso);
  }
  if (minConfidence !== null) {
    where.push("confidence >= ?");
    params.push(minConfidence);
  }

  const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  params.push(limit, offset);

  return {
    sql: `SELECT source_ip, first_seen, last_seen, score, confidence, confidence_reasons_json,
       unique_traps_json, protocols_json, country_code, asn, as_name
     FROM ip_profiles
     ${whereClause}
     ORDER BY confidence DESC, score DESC, last_seen DESC
     LIMIT ? OFFSET ?`,
    params,
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

export function ipIocsFromRequest(request: Request, options?: IpIocsQueryOptions): IpIocsQuery | Response {
  return buildIpIocsQuery(urlOf(request), options);
}
