import type { Env } from "./types.js";
import { MMDB_R2_KEY, resetMmdbReaderCache } from "../../../functions/_lib/ipinfoMmdb.js";

const IPINFO_MMDB_URL = (token: string) => `https://ipinfo.io/data/ipinfo_lite.mmdb?token=${token}`;

type SyncResult = { updated: boolean; bytes?: number; skipped?: boolean };

function skipped(bytes?: number): SyncResult {
  return bytes !== undefined ? { updated: false, skipped: true, bytes } : { updated: false, skipped: true };
}

// Compare R2 metadata against IPinfo HEAD before downloading the full MMDB.
// IPinfo may not support HEAD; when it does, etag/content-length avoid redundant transfers.
export async function syncIpinfoMmdb(
  env: Env,
  opts?: { force?: boolean }
): Promise<SyncResult> {
  if (!env.IPINFO_TOKEN) throw new Error("IPINFO_TOKEN is not configured");

  const existing = await env.EVENTS_BUCKET.head(MMDB_R2_KEY);
  const storedEtag = existing?.customMetadata?.etag;
  const storedSize = existing?.size;

  let remoteEtag: string | null = null;
  let remoteSize: number | null = null;

  if (!opts?.force) {
    const headResponse = await fetch(IPINFO_MMDB_URL(env.IPINFO_TOKEN), { method: "HEAD" });
    if (headResponse.ok) {
      remoteEtag = headResponse.headers.get("etag");
      const contentLength = headResponse.headers.get("content-length");
      if (contentLength) {
        const parsed = Number(contentLength);
        if (Number.isFinite(parsed) && parsed > 0) remoteSize = parsed;
      }
    }

    if (existing) {
      if (remoteEtag && storedEtag === remoteEtag) {
        return skipped(storedSize);
      }
      if (remoteSize !== null && storedSize === remoteSize) {
        return skipped(remoteSize);
      }
    }
  }

  const response = await fetch(IPINFO_MMDB_URL(env.IPINFO_TOKEN));
  if (!response.ok) throw new Error(`IPinfo MMDB fetch failed: ${response.status}`);

  const etag = response.headers.get("etag") ?? remoteEtag;
  const contentLength = response.headers.get("content-length");
  const declaredSize = contentLength ? Number(contentLength) : null;

  if (!opts?.force && existing) {
    if (etag && storedEtag === etag) {
      return skipped(storedSize);
    }
    if (declaredSize !== null && storedSize === declaredSize) {
      return skipped(declaredSize);
    }
  }

  const data = await response.arrayBuffer();
  const bytes = data.byteLength;

  if (!opts?.force && existing?.size === bytes) {
    return skipped(bytes);
  }

  const customMetadata: Record<string, string> = { synced_at: new Date().toISOString() };
  if (etag) customMetadata.etag = etag;

  await env.EVENTS_BUCKET.put(MMDB_R2_KEY, data, { customMetadata });

  resetMmdbReaderCache();

  return { updated: true, bytes };
}
