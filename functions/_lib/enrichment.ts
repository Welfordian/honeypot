import type { D1Database } from "@cloudflare/workers-types";
import { createMmdbFetcher, type MmdbBucket } from "./ipinfoMmdb";

export interface IpEnrichmentFields {
  country_code: string | null;
  asn: number | null;
  as_name: string | null;
}

export type EnrichmentFetcher = (ip: string) => Promise<IpEnrichmentFields | null>;

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function parseIpv4(ip: string): number[] | null {
  if (!IPV4_RE.test(ip)) return null;
  const octets = ip.split(".").map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
  return octets;
}

function ipv4InRange(octets: number[], network: [number, number, number, number], prefix: number): boolean {
  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return false;
  const ip = ((a << 24) >>> 0) | ((b << 16) >>> 0) | ((c << 8) >>> 0) | d;
  const [na, nb, nc, nd] = network;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const net = ((na << 24) >>> 0) | ((nb << 16) >>> 0) | ((nc << 8) >>> 0) | nd;
  return (ip & mask) === (net & mask);
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  const octets = parseIpv4(ip);
  if (!octets) return true;
  return (
    ipv4InRange(octets, [10, 0, 0, 0], 8) ||
    ipv4InRange(octets, [172, 16, 0, 0], 12) ||
    ipv4InRange(octets, [192, 168, 0, 0], 16) ||
    ipv4InRange(octets, [127, 0, 0, 0], 8) ||
    ipv4InRange(octets, [169, 254, 0, 0], 16) ||
    ipv4InRange(octets, [0, 0, 0, 0], 8) ||
    ipv4InRange(octets, [100, 64, 0, 0], 10) ||
    ipv4InRange(octets, [192, 0, 0, 0], 24) ||
    ipv4InRange(octets, [198, 18, 0, 0], 15) ||
    ipv4InRange(octets, [224, 0, 0, 0], 4) ||
    ipv4InRange(octets, [240, 0, 0, 0], 4)
  );
}

function expandIpv6(ip: string): bigint | null {
  const lower = ip.toLowerCase();
  if (!IPV6_RE.test(lower) || lower.includes("..")) return null;

  let head = lower;
  let tail = "";
  const split = lower.split("::");
  if (split.length > 2) return null;
  if (split.length === 2) {
    head = split[0] ?? "";
    tail = split[1] ?? "";
  }

  const headParts = head ? head.split(":").filter(Boolean) : [];
  const tailParts = tail ? tail.split(":").filter(Boolean) : [];
  const missing = 8 - headParts.length - tailParts.length;
  if (missing < 0) return null;

  const parts = [...headParts, ...Array.from({ length: missing }, () => "0"), ...tailParts];
  if (parts.length !== 8) return null;

  let value = 0n;
  for (const part of parts) {
    if (part.length > 4 || !/^[0-9a-f]+$/.test(part)) return null;
    value = (value << 16n) + BigInt(parseInt(part, 16));
  }
  return value;
}

function ipv6Matches(value: bigint, prefix: bigint, length: number): boolean {
  if (length === 0) return true;
  const shift = 128n - BigInt(length);
  return (value >> shift) === (prefix >> shift);
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const value = expandIpv6(ip);
  if (value === null) return true;
  return (
    value === 0n ||
    ipv6Matches(value, 0x00000000000000000000000000000001n, 128) ||
    ipv6Matches(value, 0xfe800000000000000000000000000000n, 10) ||
    ipv6Matches(value, 0xfc000000000000000000000000000000n, 7) ||
    ipv6Matches(value, 0xff000000000000000000000000000000n, 8)
  );
}

export function isValidIpAddress(ip: string): boolean {
  const trimmed = ip.trim();
  if (!trimmed || trimmed.length > 64) return false;
  if (parseIpv4(trimmed)) return true;
  return expandIpv6(trimmed) !== null;
}

export function isEnrichablePublicIp(ip: string): boolean {
  if (!isValidIpAddress(ip)) return false;
  if (ip.includes(".")) return !isPrivateOrReservedIpv4(ip);
  return !isPrivateOrReservedIpv6(ip);
}

export function needsEnrichment(row: {
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}): boolean {
  return row.country_code == null && row.asn == null && row.as_name == null;
}

export function enrichmentFromRow(row: {
  country_code?: string | null;
  asn?: number | null;
  as_name?: string | null;
}): IpEnrichmentFields {
  return {
    country_code: row.country_code ?? null,
    asn: row.asn ?? null,
    as_name: row.as_name ?? null
  };
}

function resolveFetcher(
  bucket: MmdbBucket | undefined,
  fetcher: EnrichmentFetcher | undefined
): EnrichmentFetcher | null {
  if (fetcher) return fetcher;
  if (bucket) return createMmdbFetcher(bucket);
  return null;
}

export async function enrichIpProfile(
  db: D1Database,
  ip: string,
  options: { bucket?: MmdbBucket; fetcher?: EnrichmentFetcher; force?: boolean } = {}
): Promise<IpEnrichmentFields | null> {
  if (!isEnrichablePublicIp(ip)) return null;

  const existing = await db
    .prepare("SELECT country_code, asn, as_name FROM ip_profiles WHERE source_ip = ?")
    .bind(ip)
    .first<{ country_code: string | null; asn: number | null; as_name: string | null }>();

  if (!existing) return null;
  if (!options.force && !needsEnrichment(existing)) return enrichmentFromRow(existing);

  const fetcher = resolveFetcher(options.bucket, options.fetcher);
  if (!fetcher) return enrichmentFromRow(existing);

  const fetched = await fetcher(ip);
  if (!fetched) {
    await db
      .prepare("UPDATE ip_profiles SET as_name = '' WHERE source_ip = ?")
      .bind(ip)
      .run();
    return { country_code: null, asn: null, as_name: "" };
  }

  await db
    .prepare("UPDATE ip_profiles SET country_code = ?, asn = ?, as_name = ? WHERE source_ip = ?")
    .bind(fetched.country_code, fetched.asn, fetched.as_name, ip)
    .run();

  return fetched;
}
