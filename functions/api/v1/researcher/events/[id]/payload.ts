import type { PagesCtx } from "../../../../../_lib/env";
import {
  clientIpFromRequest,
  logResearcherAccess,
  requireResearcherToken
} from "../../../../../_lib/researcherAuth";
import { fetchStoredEvent, redactedEventPayload } from "../../../../../_lib/researcherR2";
import { badRequest, json, token } from "../../../../../_lib/http";
import { redactPreview } from "../../../../../_lib/redaction";

interface EventPayloadRow {
  id: string;
  payload_sha256: string | null;
  payload_size: number;
  payload_preview: string;
  r2_key: string | null;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const authError = requireResearcherToken(ctx.request, ctx.env);
  if (authError) return authError;

  const raw = Array.isArray(ctx.params.id) ? ctx.params.id[0] : ctx.params.id;
  const eventId = token(raw ?? null, 120);
  if (!eventId) return badRequest("Invalid event id.");

  const event = await ctx.env.DB.prepare(
    `SELECT id, payload_sha256, payload_size, payload_preview, r2_key
     FROM events WHERE id = ?`
  )
    .bind(eventId)
    .first<EventPayloadRow>();
  if (!event) return json({ error: "not_found" }, { status: 404 });

  if (event.r2_key) {
    const stored = await fetchStoredEvent(ctx.env.EVENTS_BUCKET, event.r2_key);
    if (stored) {
      await logResearcherAccess(ctx.env.DB, {
        resource_type: "event_payload",
        resource_id: eventId,
        client_ip: clientIpFromRequest(ctx.request, ctx.env),
        user_agent: ctx.request.headers.get("user-agent")
      });
      return json({
        event_id: event.id,
        payload_sha256: event.payload_sha256,
        payload_size: event.payload_size,
        source: "r2",
        payload: redactedEventPayload(stored)
      });
    }
  }

  await logResearcherAccess(ctx.env.DB, {
    resource_type: "event_payload",
    resource_id: eventId,
    client_ip: clientIpFromRequest(ctx.request, ctx.env),
    user_agent: ctx.request.headers.get("user-agent")
  });

  return json({
    event_id: event.id,
    payload_sha256: event.payload_sha256,
    payload_size: event.payload_size,
    source: "preview",
    preview: redactPreview(event.payload_preview),
    note: event.r2_key ? "stored object unavailable" : "full bytes not retained"
  });
};
