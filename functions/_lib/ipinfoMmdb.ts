import { Buffer } from "buffer";
import { Reader, type AsnResponse } from "mmdb-lib";
import type { EnrichmentFetcher, IpEnrichmentFields } from "./enrichment";

export const MMDB_R2_KEY = "geo/ipinfo_lite.mmdb";

export type MmdbReader = Reader<AsnResponse>;

export interface MmdbBucket {
  head(key: string): Promise<{ etag?: string; uploaded?: Date; size?: number } | null>;
  get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null>;
}

export interface IpinfoLiteRecord {
  network?: string;
  country?: string;
  country_code?: string;
  continent?: string;
  continent_code?: string;
  asn?: string;
  as_name?: string;
  as_domain?: string;
}

let readerCache: { etag: string; reader: MmdbReader } | null = null;

export function parseIpinfoLiteRecord(raw: unknown): IpEnrichmentFields | null {
  const record = raw as IpinfoLiteRecord | null;
  if (!record || typeof record !== "object") return null;

  const country =
    typeof record.country_code === "string" ? record.country_code.trim().toUpperCase() : "";

  let asn: number | null = null;
  if (typeof record.asn === "string") {
    const match = /^AS(\d+)$/i.exec(record.asn.trim());
    if (match?.[1]) asn = Number.parseInt(match[1], 10);
  }

  const asName = typeof record.as_name === "string" ? record.as_name.trim() : "";

  if (!country && asn === null && !asName) return null;

  return {
    country_code: country || null,
    asn: Number.isFinite(asn) ? asn : null,
    as_name: asName || null
  };
}

export async function getMmdbReader(bucket: MmdbBucket): Promise<MmdbReader | null> {
  const head = await bucket.head(MMDB_R2_KEY);
  if (!head) return null;

  const etag = head.etag ?? head.uploaded?.toISOString() ?? "";
  if (readerCache?.etag === etag) return readerCache.reader;

  const object = await bucket.get(MMDB_R2_KEY);
  if (!object) return null;

  const reader = new Reader(Buffer.from(await object.arrayBuffer())) as MmdbReader;
  readerCache = { etag, reader };
  return reader;
}

export function lookupIpinfoLite(reader: MmdbReader, ip: string): IpEnrichmentFields | null {
  try {
    return parseIpinfoLiteRecord(reader.get(ip));
  } catch {
    return null;
  }
}

export function createMmdbFetcher(bucket: MmdbBucket): EnrichmentFetcher {
  return async (ip: string) => {
    const reader = await getMmdbReader(bucket);
    if (!reader) return null;
    return lookupIpinfoLite(reader, ip);
  };
}

export function resetMmdbReaderCache(): void {
  readerCache = null;
}
