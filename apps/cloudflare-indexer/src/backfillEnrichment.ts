import { enrichIpProfile } from "../../../functions/_lib/enrichment.js";
import type { Env } from "./types.js";

export async function backfillEnrichment(
  env: Env,
  limit: number
): Promise<{ processed: number; enriched: number; failed: number }> {
  const rows = await env.DB.prepare(
    "SELECT source_ip FROM ip_profiles WHERE country_code IS NULL AND asn IS NULL AND as_name IS NULL LIMIT ?"
  )
    .bind(limit)
    .all<{ source_ip: string }>();

  let enriched = 0;
  let failed = 0;

  for (const row of rows.results) {
    try {
      const result = await enrichIpProfile(env.DB, row.source_ip, { bucket: env.EVENTS_BUCKET });
      if (result) enriched += 1;
      else failed += 1;
    } catch (error) {
      console.warn("Backfill enrichment failed", row.source_ip, error);
      failed += 1;
    }
  }

  return { processed: rows.results.length, enriched, failed };
}
