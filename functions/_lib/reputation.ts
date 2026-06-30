import type { D1Database } from "@cloudflare/workers-types";
import type { Env } from "./env";

export interface GreynoiseReputation {
  classification: string | null;
  name?: string | null;
  tags: string[];
}

export interface VirusTotalReputation {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

export interface ReputationSummary {
  providers: {
    greynoise?: GreynoiseReputation;
    virustotal?: VirusTotalReputation;
  };
}

interface ReputationCacheRow {
  source_ip: string;
  provider: string;
  classification: string | null;
  tags_json: string;
  raw_json: string | null;
  fetched_at: string;
  expires_at: string;
}

const TTL_MS = 24 * 60 * 60 * 1000;

export type ReputationFetcher = typeof fetch;

export async function fetchGreynoiseIp(
  ip: string,
  apiKey: string,
  fetcher: ReputationFetcher = fetch
): Promise<GreynoiseReputation | null> {
  try {
    const response = await fetcher(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers: {
        Accept: "application/json",
        key: apiKey
      },
      signal: AbortSignal.timeout(5_000)
    });
    if (!response.ok) return null;
    const data = (await response.json()) as Record<string, unknown>;
    return {
      classification: typeof data.classification === "string" ? data.classification : null,
      name: typeof data.name === "string" ? data.name : null,
      tags: Array.isArray(data.tags)
        ? data.tags.filter((tag): tag is string => typeof tag === "string")
        : []
    };
  } catch {
    return null;
  }
}

export async function fetchVirusTotalHash(
  sha256: string,
  apiKey: string,
  fetcher: ReputationFetcher = fetch
): Promise<VirusTotalReputation | null> {
  try {
    const response = await fetcher(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: {
        Accept: "application/json",
        "x-apikey": apiKey
      },
      signal: AbortSignal.timeout(5_000)
    });
    if (!response.ok) return null;
    const body = (await response.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
    };
    const stats = body.data?.attributes?.last_analysis_stats;
    if (!stats) return null;
    return {
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0
    };
  } catch {
    return null;
  }
}

function parseTagsJson(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((tag): tag is string => typeof tag === "string") : [];
  } catch {
    return [];
  }
}

function greynoiseFromCache(row: ReputationCacheRow): GreynoiseReputation {
  return {
    classification: row.classification,
    tags: parseTagsJson(row.tags_json)
  };
}

function virustotalFromCache(row: ReputationCacheRow): VirusTotalReputation | null {
  if (!row.raw_json) return null;
  try {
    const parsed = JSON.parse(row.raw_json) as VirusTotalReputation;
    if (
      typeof parsed.malicious !== "number" ||
      typeof parsed.suspicious !== "number" ||
      typeof parsed.harmless !== "number" ||
      typeof parsed.undetected !== "number"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

async function readCacheRow(
  db: D1Database,
  sourceIp: string,
  provider: string
): Promise<ReputationCacheRow | null> {
  const row = await db
    .prepare(
      `SELECT source_ip, provider, classification, tags_json, raw_json, fetched_at, expires_at
       FROM ip_reputation_cache
       WHERE source_ip = ? AND provider = ?`
    )
    .bind(sourceIp, provider)
    .first<ReputationCacheRow>();
  if (!row) return null;
  if (!Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }
  return row;
}

async function writeCacheRow(
  db: D1Database,
  sourceIp: string,
  provider: string,
  values: {
    classification: string | null;
    tags: string[];
    raw: unknown;
  }
): Promise<void> {
  const now = new Date();
  const fetchedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + TTL_MS).toISOString();
  await db
    .prepare(
      `INSERT INTO ip_reputation_cache (source_ip, provider, classification, tags_json, raw_json, fetched_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(source_ip) DO UPDATE SET
         provider = excluded.provider,
         classification = excluded.classification,
         tags_json = excluded.tags_json,
         raw_json = excluded.raw_json,
         fetched_at = excluded.fetched_at,
         expires_at = excluded.expires_at`
    )
    .bind(
      sourceIp,
      provider,
      values.classification,
      JSON.stringify(values.tags),
      JSON.stringify(values.raw),
      fetchedAt,
      expiresAt
    )
    .run();
}

export async function getIpReputation(
  db: D1Database,
  ip: string,
  env: Pick<Env, "GREYNOISE_API_KEY">,
  fetcher: ReputationFetcher = fetch
): Promise<ReputationSummary> {
  const summary: ReputationSummary = { providers: {} };
  const apiKey = env.GREYNOISE_API_KEY;
  if (!apiKey) return summary;

  const cached = await readCacheRow(db, ip, "greynoise");
  if (cached) {
    summary.providers.greynoise = greynoiseFromCache(cached);
    if (cached.raw_json) {
      try {
        const raw = JSON.parse(cached.raw_json) as GreynoiseReputation;
        if (typeof raw.name === "string") summary.providers.greynoise.name = raw.name;
      } catch {
        // ignore malformed cache payload
      }
    }
    return summary;
  }

  const fetched = await fetchGreynoiseIp(ip, apiKey, fetcher);
  if (!fetched) return summary;

  await writeCacheRow(db, ip, "greynoise", {
    classification: fetched.classification,
    tags: fetched.tags,
    raw: fetched
  });
  summary.providers.greynoise = fetched;
  return summary;
}

export async function getHashReputation(
  db: D1Database,
  sha256: string,
  env: Pick<Env, "VIRUSTOTAL_API_KEY">,
  fetcher: ReputationFetcher = fetch
): Promise<ReputationSummary> {
  const summary: ReputationSummary = { providers: {} };
  const apiKey = env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return summary;

  const cached = await readCacheRow(db, sha256, "virustotal");
  if (cached) {
    const stats = virustotalFromCache(cached);
    if (stats) summary.providers.virustotal = stats;
    return summary;
  }

  const fetched = await fetchVirusTotalHash(sha256, apiKey, fetcher);
  if (!fetched) return summary;

  await writeCacheRow(db, sha256, "virustotal", {
    classification: null,
    tags: [],
    raw: fetched
  });
  summary.providers.virustotal = fetched;
  return summary;
}
