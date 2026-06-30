import type { Env } from "./types.js";
import { MMDB_R2_KEY, resetMmdbReaderCache } from "../../../functions/_lib/ipinfoMmdb.js";

export async function syncIpinfoMmdb(env: Env): Promise<{ updated: boolean; bytes?: number; skipped?: boolean }> {
  if (!env.IPINFO_TOKEN) throw new Error("IPINFO_TOKEN is not configured");

  const response = await fetch(`https://ipinfo.io/data/ipinfo_lite.mmdb?token=${env.IPINFO_TOKEN}`);
  if (!response.ok) throw new Error(`IPinfo MMDB fetch failed: ${response.status}`);

  const data = await response.arrayBuffer();
  const bytes = data.byteLength;

  const existing = await env.EVENTS_BUCKET.head(MMDB_R2_KEY);
  if (existing?.size === bytes) return { updated: false, skipped: true, bytes };

  await env.EVENTS_BUCKET.put(MMDB_R2_KEY, data, {
    customMetadata: { synced_at: new Date().toISOString() }
  });

  resetMmdbReaderCache();

  return { updated: true, bytes };
}
