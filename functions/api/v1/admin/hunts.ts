import type { PagesCtx } from "../../../_lib/env";
import { json } from "../../../_lib/http";

function unauthorized(): Response {
  return json({ error: "unauthorized" }, { status: 401 });
}

function misconfigured(): Response {
  return json({ error: "indexer_not_configured" }, { status: 503 });
}

async function proxyIndexer(request: Request, env: PagesCtx["env"], path: string): Promise<Response> {
  const token = request.headers.get("x-indexer-token");
  if (!env.INDEXER_ADMIN_TOKEN || token !== env.INDEXER_ADMIN_TOKEN) return unauthorized();
  if (!env.INDEXER_URL) return misconfigured();

  const url = new URL(path, env.INDEXER_URL.replace(/\/$/, "") + "/");
  const incoming = new URL(request.url);
  incoming.searchParams.forEach((value, key) => url.searchParams.set(key, value));

  const headers = new Headers({ "x-indexer-token": env.INDEXER_ADMIN_TOKEN });
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);

  const init: RequestInit = {
    method: request.method,
    headers
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = await request.text();
  }

  const response = await fetch(url.toString(), init);
  const body = await response.text();
  return new Response(body, {
    status: response.status,
    headers: {
      "content-type": response.headers.get("content-type") ?? "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = new URL(ctx.request.url);
  const path = url.searchParams.get("webhooks") === "1"
    ? "/internal/admin/webhook-subscriptions"
    : "/internal/admin/hunt-rules";
  return proxyIndexer(ctx.request, ctx.env, path);
};

export const onRequestPost: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = new URL(ctx.request.url);
  const path = url.searchParams.get("webhooks") === "1"
    ? "/internal/admin/webhook-subscriptions"
    : "/internal/admin/hunt-rules";
  return proxyIndexer(ctx.request, ctx.env, path);
};

export const onRequestDelete: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  return proxyIndexer(ctx.request, ctx.env, "/internal/admin/webhook-subscriptions");
};
