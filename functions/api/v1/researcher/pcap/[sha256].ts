import type { PagesCtx } from "../../../../_lib/env";
import {
  clientIpFromRequest,
  logResearcherAccess,
  requireResearcherToken
} from "../../../../_lib/researcherAuth";
import { badRequest, publicSha256 } from "../../../../_lib/http";

interface PcapChunkRow {
  r2_key: string;
  expires_at: string;
  sha256: string;
  capture_id: string;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const authError = requireResearcherToken(ctx.request, ctx.env);
  if (authError) return authError;

  const raw = Array.isArray(ctx.params.sha256) ? ctx.params.sha256[0] : ctx.params.sha256;
  const sha256 = publicSha256(raw ?? null);
  if (!sha256) return badRequest("Invalid SHA-256 hash.");

  const chunk = await ctx.env.DB.prepare(
    `SELECT r2_key, expires_at, sha256, capture_id FROM pcap_chunks WHERE sha256 = ?`
  )
    .bind(sha256)
    .first<PcapChunkRow>();
  if (!chunk) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
    });
  }

  const now = new Date().toISOString();
  if (chunk.expires_at <= now) {
    return new Response(JSON.stringify({ error: "not_found", message: "PCAP chunk expired." }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
    });
  }

  const object = await ctx.env.EVENTS_BUCKET.get(chunk.r2_key);
  if (!object) {
    return new Response(JSON.stringify({ error: "not_found", message: "PCAP object missing." }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
    });
  }

  const bytes = await object.arrayBuffer();
  const isGzip = new Uint8Array(bytes, 0, 2)[0] === 0x1f && new Uint8Array(bytes, 0, 2)[1] === 0x8b;
  const filename = isGzip ? `${sha256}.pcap.gz` : `${sha256}.pcap`;

  await logResearcherAccess(ctx.env.DB, {
    resource_type: "pcap",
    resource_id: sha256,
    client_ip: clientIpFromRequest(ctx.request, ctx.env),
    user_agent: ctx.request.headers.get("user-agent")
  });

  const headers = new Headers({
    "content-type": "application/vnd.tcpdump",
    "content-disposition": `attachment; filename="${filename}"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  if (isGzip) headers.set("content-encoding", "gzip");

  return new Response(bytes, { status: 200, headers });
};
