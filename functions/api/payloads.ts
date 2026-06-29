import type { PagesCtx } from "../_lib/env";
import { json, parseLimit, urlOf } from "../_lib/http";
import { redactPreview } from "../_lib/redaction";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const limit = parseLimit(urlOf(ctx.request), 100, 500);
  const result = await ctx.env.DB.prepare(
    `SELECT p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count,
       COALESCE(MAX(e.confidence), 0) AS max_confidence,
       COUNT(DISTINCT e.source_ip) AS unique_ips
     FROM payloads p
     LEFT JOIN events e ON e.payload_sha256 = p.sha256
     GROUP BY p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count
     ORDER BY p.event_count DESC, p.last_seen DESC
     LIMIT ?`
  ).bind(limit).all();
  return json({
    payloads: result.results.map((row) => ({
      ...row,
      preview: redactPreview(String(row.preview ?? ""))
    }))
  });
};
