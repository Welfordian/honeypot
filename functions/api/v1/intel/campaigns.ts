import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";

const SINCE_CLAUSE = `occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`;

interface PayloadCampaignRow {
  sha256: string;
  event_count: number;
  unique_ips: number;
  max_confidence: number;
}

interface BehavioralCampaignRow {
  fingerprint: string;
  traps: string;
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
    ctx.env.DB.prepare(
      `SELECT payload_sha256 AS sha256, COUNT(*) AS event_count,
              COUNT(DISTINCT source_ip) AS unique_ips, MAX(confidence) AS max_confidence
       FROM events
       WHERE payload_sha256 IS NOT NULL
         AND ${SINCE_CLAUSE}
       GROUP BY payload_sha256
       HAVING event_count >= 2
       ORDER BY event_count DESC
       LIMIT 20`
    ).bind(since).all<PayloadCampaignRow>(),
    ctx.env.DB.prepare(
      `WITH window_events AS (
         SELECT source_ip, trap, confidence
         FROM events
         WHERE ${SINCE_CLAUSE}
       ),
       ip_traps AS (
         SELECT source_ip, trap
         FROM window_events
         GROUP BY source_ip, trap
       ),
       ip_fingerprints AS (
         SELECT source_ip,
           (SELECT GROUP_CONCAT(trap, '|')
            FROM (SELECT trap FROM ip_traps it WHERE it.source_ip = ot.source_ip ORDER BY trap ASC)
           ) AS fingerprint
         FROM (SELECT DISTINCT source_ip FROM ip_traps) ot
       ),
       campaign_groups AS (
         SELECT fingerprint,
                COUNT(DISTINCT source_ip) AS unique_ips,
                GROUP_CONCAT(DISTINCT source_ip) AS source_ips
         FROM ip_fingerprints
         WHERE fingerprint IS NOT NULL AND fingerprint != ''
         GROUP BY fingerprint
         HAVING unique_ips >= 2
       )
       SELECT g.fingerprint,
              g.fingerprint AS traps,
              g.unique_ips,
              g.source_ips,
              (SELECT COUNT(*) FROM window_events w
               JOIN ip_fingerprints f ON f.source_ip = w.source_ip
               WHERE f.fingerprint = g.fingerprint) AS event_count,
              (SELECT MAX(confidence) FROM window_events w
               JOIN ip_fingerprints f ON f.source_ip = w.source_ip
               WHERE f.fingerprint = g.fingerprint) AS max_confidence
       FROM campaign_groups g
       ORDER BY unique_ips DESC, event_count DESC
       LIMIT 20`
    ).bind(since).all<BehavioralCampaignRow>()
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

  return cachedJson({
    payload_campaigns: payloadCampaigns.results,
    behavioral_campaigns: behavioral
  });
};
