import type { PagesCtx } from "../../_lib/env";
import { json, parseSinceHours, urlOf } from "../../_lib/http";
import { sumRollupCounts, sumRollupEventTotals, sumRollupTimeline } from "../../_lib/rollups";
import { isOperationalSensorId } from "../../_lib/sensorStatus";

const OVERVIEW_CACHE = { headers: { "cache-control": "public, max-age=60, stale-while-revalidate=300" } };

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [totals, timeline, topIps, topProtocols, topTraps, topSeverities, sensors] = await Promise.all([
    sumRollupEventTotals(ctx.env.DB, since).then((rollupTotals) =>
      ctx.env.DB.prepare(
        `SELECT MAX(severity) AS max_severity
         FROM events
         WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
        .bind(since)
        .first<{ max_severity: number | null }>()
        .then((severity) => ({
          events: rollupTotals.events,
          unique_ips: rollupTotals.unique_ips,
          max_severity: severity?.max_severity ?? 0
        }))
    ),
    sumRollupTimeline(ctx.env.DB, since),
    ctx.env.DB.prepare(
      `SELECT source_ip AS key, COUNT(*) AS count, MAX(severity) AS max_severity
       FROM events
       WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY source_ip
       ORDER BY count DESC
       LIMIT 10`
    )
      .bind(since)
      .all(),
    sumRollupCounts(ctx.env.DB, "protocol", since, 10),
    sumRollupCounts(ctx.env.DB, "trap", since, 10),
    sumRollupCounts(ctx.env.DB, "severity", since, 20).then((rows) =>
      rows.sort((a, b) => Number(b.key) - Number(a.key))
    ),
    ctx.env.DB.prepare(
      `SELECT sensor_id, last_seen, last_protocol, last_trap, event_count
       FROM sensor_health
       ORDER BY last_seen DESC
       LIMIT 50`
    ).all()
  ]);

  return json(
    {
      totals,
      timeline,
      topIps: topIps.results,
      topProtocols,
      topTraps,
      topSeverities,
      sensors: sensors.results.filter(
        (sensor) => typeof sensor.sensor_id === "string" && isOperationalSensorId(sensor.sensor_id)
      )
    },
    OVERVIEW_CACHE
  );
};
