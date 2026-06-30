import type { PagesCtx } from "../../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../../_lib/http";
import { sumRollupCounts } from "../../../_lib/rollups";

const INTEL_CACHE = { headers: { "cache-control": "public, max-age=60, stale-while-revalidate=300" } };

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [topAttackers, topConfidenceReasons, topTags, credentialAttempts, highConfidenceIps, campaigns] =
    await Promise.all([
      ctx.env.DB.prepare(
        `SELECT source_ip AS key, COUNT(*) AS count, MAX(severity) AS max_severity, MAX(confidence) AS max_confidence
         FROM events
         WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         GROUP BY source_ip
         ORDER BY count DESC
         LIMIT 10`
      )
        .bind(since)
        .all(),
      sumRollupCounts(ctx.env.DB, "confidence_reason", since, 15),
      sumRollupCounts(ctx.env.DB, "tag", since, 15),
      ctx.env.DB.prepare(
        `SELECT COUNT(*) AS count
         FROM events
         WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
           AND (has_username = 1 OR has_password = 1)`
      )
        .bind(since)
        .first<{ count: number }>(),
      ctx.env.DB.prepare(
        `SELECT COUNT(DISTINCT source_ip) AS count
         FROM events
         WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
           AND confidence >= 80`
      )
        .bind(since)
        .first<{ count: number }>(),
      ctx.env.DB.prepare(
        `SELECT payload_sha256 AS sha256, COUNT(*) AS event_count,
                COUNT(DISTINCT source_ip) AS unique_ips, MAX(confidence) AS max_confidence
         FROM events
         WHERE payload_sha256 IS NOT NULL
           AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
         GROUP BY payload_sha256
         HAVING event_count >= 2
         ORDER BY event_count DESC
         LIMIT 20`
      )
        .bind(since)
        .all()
    ]);

  return cachedJson(
    {
      topAttackers: topAttackers.results,
      topConfidenceReasons,
      topTags,
      credentialAttempts: credentialAttempts?.count ?? 0,
      highConfidenceIps: highConfidenceIps?.count ?? 0,
      campaigns: campaigns.results
    },
    INTEL_CACHE
  );
};
