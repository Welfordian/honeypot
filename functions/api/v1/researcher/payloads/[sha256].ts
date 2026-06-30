import type { PagesCtx } from "../../../../_lib/env";
import {
  clientIpFromRequest,
  logResearcherAccess,
  requireResearcherToken
} from "../../../../_lib/researcherAuth";
import { fetchStoredEvent, redactedEventPayload } from "../../../../_lib/researcherR2";
import { badRequest, json, publicSha256 } from "../../../../_lib/http";
import { redactPreview } from "../../../../_lib/redaction";

interface PayloadRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  preview: string;
}

interface EventR2Row {
  r2_key: string;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const authError = requireResearcherToken(ctx.request, ctx.env);
  if (authError) return authError;

  const raw = Array.isArray(ctx.params.sha256) ? ctx.params.sha256[0] : ctx.params.sha256;
  const sha256 = publicSha256(raw ?? null);
  if (!sha256) return badRequest("Invalid SHA-256 hash.");

  const payload = await ctx.env.DB.prepare(
    `SELECT sha256, size_bytes, mime_guess, preview FROM payloads WHERE sha256 = ?`
  )
    .bind(sha256)
    .first<PayloadRow>();
  if (!payload) return json({ error: "not_found" }, { status: 404 });

  const eventWithR2 = await ctx.env.DB.prepare(
    `SELECT r2_key FROM events WHERE payload_sha256 = ? AND r2_key IS NOT NULL AND r2_key != ''
     ORDER BY occurred_at DESC LIMIT 1`
  )
    .bind(sha256)
    .first<EventR2Row>();

  if (eventWithR2?.r2_key) {
    const stored = await fetchStoredEvent(ctx.env.EVENTS_BUCKET, eventWithR2.r2_key);
    if (stored?.payload?.text || stored?.payload?.base64) {
      await logResearcherAccess(ctx.env.DB, {
        resource_type: "payload",
        resource_id: sha256,
        client_ip: clientIpFromRequest(ctx.request, ctx.env),
        user_agent: ctx.request.headers.get("user-agent")
      });
      return json({
        sha256,
        size_bytes: payload.size_bytes,
        mime_guess: payload.mime_guess,
        source: "r2",
        payload: redactedEventPayload(stored)
      });
    }
  }

  const expanded = await ctx.env.DB.prepare(
    `SELECT payload_preview FROM events
     WHERE payload_sha256 = ?
     ORDER BY LENGTH(payload_preview) DESC
     LIMIT 1`
  )
    .bind(sha256)
    .first<{ payload_preview: string }>();

  await logResearcherAccess(ctx.env.DB, {
    resource_type: "payload",
    resource_id: sha256,
    client_ip: clientIpFromRequest(ctx.request, ctx.env),
    user_agent: ctx.request.headers.get("user-agent")
  });

  return json({
    sha256,
    size_bytes: payload.size_bytes,
    preview: redactPreview(expanded?.payload_preview ?? payload.preview),
    note: "full bytes not retained"
  });
};
