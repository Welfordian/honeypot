import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseLimit, parseOffset, urlOf } from "../../../_lib/http";
import { redactPreview } from "../../../_lib/redaction";

interface PayloadRow {
  sha256: string;
  size_bytes: number;
  mime_guess: string;
  preview: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  max_confidence: number;
  unique_ips: number;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const limit = parseLimit(url, 100, 500);
  const offset = parseOffset(url);
  const result = await ctx.env.DB.prepare(
    `SELECT p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count,
       COALESCE(MAX(e.confidence), 0) AS max_confidence,
       COUNT(DISTINCT e.source_ip) AS unique_ips
     FROM payloads p
     LEFT JOIN events e ON e.payload_sha256 = p.sha256
     GROUP BY p.sha256, p.size_bytes, p.mime_guess, p.preview, p.first_seen, p.last_seen, p.event_count
     ORDER BY p.event_count DESC, p.last_seen DESC
     LIMIT ? OFFSET ?`
  ).bind(limit + 1, offset).all<PayloadRow>();
  const rows = result.results.slice(0, limit);

  return cachedJson({
    payloads: rows.map((row) => ({
      ...row,
      preview: redactPreview(row.preview)
    })),
    next_offset: result.results.length > limit ? offset + limit : null
  });
};
