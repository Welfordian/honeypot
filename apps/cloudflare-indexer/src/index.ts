import type { Env, R2NotificationBody, StoredR2Event } from "./types.js";
import { backfillEnrichment } from "./backfillEnrichment.js";
import { indexStoredEvent } from "./indexEvent.js";
import { handleIngest, handlePcapIngest } from "./ingest.js";
import { publishLiveEvent } from "./live.js";
import { recomputeConfidence } from "./recompute.js";
import { syncIpinfoMmdb } from "./syncIpinfoMmdb.js";

function json(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", headers.get("cache-control") ?? "no-store");
  return Response.json(body, init?.status ? { headers, status: init.status } : { headers });
}

function objectKeyFromMessage(body: unknown): string | null {
  const notification = body as R2NotificationBody;
  return notification.object?.key ?? notification.object?.name ?? notification.key ?? null;
}

async function readEvent(env: Env, key: string): Promise<StoredR2Event> {
  const object = await env.EVENTS_BUCKET.get(key);
  if (!object) throw new Error(`R2 object not found: ${key}`);
  return JSON.parse(await object.text()) as StoredR2Event;
}

async function indexKey(env: Env, key: string): Promise<void> {
  if (key.startsWith(`${env.PCAP_PREFIX ?? "private-pcap"}/`)) return;
  const event = await readEvent(env, key);
  await publishLiveEvent(env, await indexStoredEvent(env.DB, event, key, env.EVENTS_BUCKET));
}

function suppressedSourceIps(env: Env): string[] {
  return (env.SUPPRESSED_SOURCE_IPS ?? "")
    .split(",")
    .map((ip) => ip.trim())
    .filter(Boolean);
}

async function scrubSuppressedR2(env: Env): Promise<{ scanned: number; deleted: number }> {
  const suppressed = suppressedSourceIps(env);
  let cursor: string | undefined;
  let scanned = 0;
  let deleted = 0;

  if (!suppressed.length) return { scanned, deleted };

  do {
    const options: R2ListOptions = { prefix: "raw/", limit: 100 };
    if (cursor) options.cursor = cursor;
    const listed = await env.EVENTS_BUCKET.list(options);
    for (const object of listed.objects) {
      scanned += 1;
      const stored = await env.EVENTS_BUCKET.get(object.key);
      if (!stored) continue;
      const body = await stored.text();
      if (suppressed.some((ip) => body.includes(ip))) {
        await env.EVENTS_BUCKET.delete(object.key);
        deleted += 1;
      }
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  const pcapRows = await env.DB.prepare("SELECT capture_id, r2_key, source_ips_json FROM pcap_chunks").all<{
    capture_id: string;
    r2_key: string;
    source_ips_json: string;
  }>();

  for (const row of pcapRows.results) {
    scanned += 1;
    let sourceIps: string[] = [];
    try {
      const parsed = JSON.parse(row.source_ips_json);
      sourceIps = Array.isArray(parsed) ? parsed.filter((ip): ip is string => typeof ip === "string") : [];
    } catch {
      sourceIps = [];
    }
    if (!sourceIps.some((ip) => suppressed.includes(ip))) continue;
    await env.EVENTS_BUCKET.delete(row.r2_key);
    await env.DB.prepare("DELETE FROM pcap_chunks WHERE capture_id = ?").bind(row.capture_id).run();
    deleted += 1;
  }

  return { scanned, deleted };
}

async function expirePcapChunks(env: Env): Promise<{ expired: number; deleted: number }> {
  const now = new Date().toISOString();
  const rows = await env.DB.prepare("SELECT capture_id, r2_key FROM pcap_chunks WHERE expires_at <= ? LIMIT 100").bind(now).all<{
    capture_id: string;
    r2_key: string;
  }>();
  let deleted = 0;

  for (const row of rows.results) {
    await env.EVENTS_BUCKET.delete(row.r2_key);
    await env.DB.prepare("DELETE FROM pcap_chunks WHERE capture_id = ?").bind(row.capture_id).run();
    deleted += 1;
  }

  return { expired: rows.results.length, deleted };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") return json({ ok: true });

    if (url.pathname === "/internal/ingest/events") {
      return handleIngest(request, env);
    }

    if (url.pathname === "/internal/ingest/pcap") {
      return handlePcapIngest(request, env);
    }

    if (url.pathname === "/index-object" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      const body = (await request.json()) as { key?: string };
      if (!body.key) return json({ error: "missing_key" }, { status: 400 });
      await indexKey(env, body.key);
      return json({ indexed: true, key: body.key });
    }

    if (url.pathname === "/internal/admin/scrub-suppressed-r2" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      return json(await scrubSuppressedR2(env));
    }

    if (url.pathname === "/internal/admin/expire-pcap" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      return json(await expirePcapChunks(env));
    }

    if (url.pathname === "/internal/admin/recompute-confidence" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      return json(await recomputeConfidence(env, body));
    }

    if (url.pathname === "/internal/admin/sync-ipinfo-mmdb" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      return json(await syncIpinfoMmdb(env));
    }

    if (url.pathname === "/internal/admin/backfill-enrichment" && request.method === "POST") {
      const token = request.headers.get("x-indexer-token");
      if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return json({ error: "unauthorized" }, { status: 401 });
      const body = (await request.json().catch(() => ({}))) as { limit?: number };
      const limit = typeof body.limit === "number" && body.limit > 0 ? body.limit : 200;
      return json(await backfillEnrichment(env, limit));
    }

    return json({ error: "not_found" }, { status: 404 });
  },

  async queue(batch: MessageBatch, env: Env): Promise<void> {
    for (const message of batch.messages) {
      const key = objectKeyFromMessage(message.body);
      if (!key) {
        console.warn("R2 notification missing object key", message.body);
        continue;
      }
      await indexKey(env, key);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(expirePcapChunks(env));
    if (env.IPINFO_TOKEN) {
      ctx.waitUntil(syncIpinfoMmdb(env).catch((error) => console.error("IPinfo MMDB sync failed", error)));
    }
  }
};
