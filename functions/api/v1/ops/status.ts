import type { PagesCtx } from "../../../_lib/env";
import { cachedJson } from "../../../_lib/http";
import { sumRollupEventTotals } from "../../../_lib/rollups";
import { isOperationalSensorId, sensorStatusFromLastSeen } from "../../../_lib/sensorStatus";

interface SensorRow {
  sensor_id: string;
  last_seen: string;
  last_protocol: string;
  last_trap: string;
  event_count: number;
}

const OPS_CACHE = { headers: { "cache-control": "public, max-age=60, stale-while-revalidate=300" } };

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const since24h = "-24 hours";
  const expiringSoon = "datetime('now', '+48 hours')";

  const [sensorRows, ingest, capture, totals24h] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT sensor_id, last_seen, last_protocol, last_trap, event_count
       FROM sensor_health
       ORDER BY last_seen DESC
       LIMIT 100`
    ).all<SensorRow>(),
    ctx.env.DB.prepare(
      `SELECT last_event_at, last_received_at FROM ingest_watermark WHERE id = 1`
    ).first<{ last_event_at: string | null; last_received_at: string | null }>(),
    ctx.env.DB.prepare(
      `SELECT
         COUNT(*) AS chunks_24h,
         COALESCE(SUM(packet_count), 0) AS packets_24h,
         COALESCE(SUM(size_bytes), 0) AS bytes_24h,
         COALESCE(SUM(CASE WHEN expires_at <= ${expiringSoon} THEN 1 ELSE 0 END), 0) AS expiring_soon
       FROM pcap_chunks
       WHERE uploaded_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    ).bind(since24h).first(),
    sumRollupEventTotals(ctx.env.DB, since24h)
  ]);

  const now = Date.now();
  const sensors = sensorRows.results
    .filter((sensor) => isOperationalSensorId(sensor.sensor_id))
    .map((sensor) => ({
      ...sensor,
      status: sensorStatusFromLastSeen(sensor.last_seen, now)
    }));

  return cachedJson(
    {
      sensors,
      ingest: ingest ?? { last_event_at: null, last_received_at: null },
      capture: capture ?? { chunks_24h: 0, packets_24h: 0, bytes_24h: 0, expiring_soon: 0 },
      totals24h
    },
    OPS_CACHE
  );
};
