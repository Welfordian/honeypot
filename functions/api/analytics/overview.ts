import type { PagesCtx } from "../../_lib/env";
import { json, parseSinceHours, urlOf } from "../../_lib/http";
import { isOperationalSensorId } from "../../_lib/sensorStatus";

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;
  const [totals, timeline, topIps, topProtocols, topTraps, topSeverities, sensors] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT COUNT(*) AS events, COUNT(DISTINCT source_ip) AS unique_ips, MAX(severity) AS max_severity
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    ).bind(since).first(),
    ctx.env.DB.prepare(
      `SELECT substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket, COUNT(*) AS count
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket ORDER BY bucket`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT source_ip AS key, COUNT(*) AS count, MAX(severity) AS max_severity
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY source_ip ORDER BY count DESC LIMIT 10`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT protocol AS key, COUNT(*) AS count
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY protocol ORDER BY count DESC LIMIT 10`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT trap AS key, COUNT(*) AS count
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY trap ORDER BY count DESC LIMIT 10`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT severity AS key, COUNT(*) AS count
       FROM events WHERE occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY severity ORDER BY severity DESC`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT sensor_id, last_seen, last_protocol, last_trap, event_count
       FROM sensor_health ORDER BY last_seen DESC LIMIT 50`
    ).all()
  ]);

  return json({
    totals: totals ?? { events: 0, unique_ips: 0, max_severity: 0 },
    timeline: timeline.results,
    topIps: topIps.results,
    topProtocols: topProtocols.results,
    topTraps: topTraps.results,
    topSeverities: topSeverities.results,
    sensors: sensors.results.filter((sensor) =>
      typeof sensor.sensor_id === "string" && isOperationalSensorId(sensor.sensor_id)
    )
  }, { headers: { "cache-control": "public, max-age=10" } });
};
