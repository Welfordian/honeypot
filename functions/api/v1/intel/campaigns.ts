import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import { FAST_CACHE, topPayloadCampaigns } from "../../../_lib/rollups";

interface BehavioralCampaignRow {
  fingerprint: string;
  unique_ips: number;
  event_count: number;
  max_confidence: number;
  source_ips: string;
}

async function fingerprintId(fingerprint: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fingerprint));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 168, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [payloadCampaigns, behavioralCampaigns] = await Promise.all([
    topPayloadCampaigns(ctx.env.DB, since, 20),
    ctx.env.DB.prepare(
      `WITH per_ip AS (
         SELECT source_ip,
                (
                  SELECT GROUP_CONCAT(trap, '|')
                  FROM (
                    SELECT DISTINCT trap
                    FROM events e2
                    WHERE e2.source_ip = e.source_ip
                      AND e2.occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
                    ORDER BY trap
                  )
                ) AS fingerprint,
                COUNT(*) AS event_count,
                MAX(confidence) AS max_confidence
         FROM events e
         WHERE e.occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         GROUP BY source_ip
       )
       SELECT fingerprint,
              COUNT(*) AS unique_ips,
              SUM(event_count) AS event_count,
              MAX(max_confidence) AS max_confidence,
              GROUP_CONCAT(source_ip) AS source_ips
       FROM per_ip
       WHERE fingerprint IS NOT NULL AND fingerprint != ''
       GROUP BY fingerprint
       HAVING unique_ips >= 2
       ORDER BY unique_ips DESC, event_count DESC
       LIMIT 20`
    )
      .bind(since, since)
      .all<BehavioralCampaignRow>()
  ]);

  const behavioral = await Promise.all(
    behavioralCampaigns.results.map(async (row) => ({
      campaign_id: await fingerprintId(row.fingerprint),
      traps: row.fingerprint.split("|"),
      unique_ips: row.unique_ips,
      event_count: row.event_count,
      max_confidence: row.max_confidence,
      source_ips: row.source_ips.split(",").slice(0, 20)
    }))
  );

  return cachedJson(
    {
      payload_campaigns: payloadCampaigns,
      behavioral_campaigns: behavioral
    },
    FAST_CACHE
  );
};
