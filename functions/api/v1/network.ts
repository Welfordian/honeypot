import type { PagesCtx } from "../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../_lib/http";

interface CountRow {
  key: string | number;
  count: number;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [totals, timeline, topPorts, topProtocols, tcpFlags, eventKinds, topBannerIps, pcap] = await Promise.all([
    ctx.env.DB.prepare(
      `SELECT
         COUNT(*) AS events,
         COUNT(DISTINCT source_ip) AS unique_ips,
         COALESCE(SUM(packet_count), 0) AS packets,
         COALESCE(SUM(byte_count), 0) AS bytes,
         COALESCE(SUM(CASE WHEN is_aggregate = 1 THEN 1 ELSE 0 END), 0) AS aggregate_events
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    ).bind(since).first(),
    ctx.env.DB.prepare(
      `SELECT substr(occurred_at, 1, 13) || ':00:00.000Z' AS bucket, COUNT(*) AS count, COUNT(DISTINCT source_ip) AS unique_ips
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY bucket
       ORDER BY bucket ASC`
    ).bind(since).all(),
    ctx.env.DB.prepare(
      `SELECT destination_port AS key, COUNT(*) AS count
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND destination_port IS NOT NULL
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY destination_port
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<CountRow>(),
    ctx.env.DB.prepare(
      `SELECT protocol AS key, COUNT(*) AS count
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY protocol
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<CountRow>(),
    ctx.env.DB.prepare(
      `SELECT tcp_flags AS key, COUNT(*) AS count
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND tcp_flags IS NOT NULL
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY tcp_flags
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<CountRow>(),
    ctx.env.DB.prepare(
      `SELECT event_kind AS key, COUNT(*) AS count
       FROM events
       WHERE event_kind IN ('network-attempt', 'tcp-banner')
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY event_kind
       ORDER BY count DESC`
    ).bind(since).all<CountRow>(),
    ctx.env.DB.prepare(
      `SELECT source_ip AS key, COUNT(*) AS count
       FROM events
       WHERE event_kind = 'tcp-banner'
         AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
       GROUP BY source_ip
       ORDER BY count DESC
       LIMIT 20`
    ).bind(since).all<CountRow>(),
    ctx.env.DB.prepare(
      `SELECT COUNT(*) AS chunks, COALESCE(SUM(size_bytes), 0) AS bytes, COALESCE(SUM(packet_count), 0) AS packets
       FROM pcap_chunks
       WHERE uploaded_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
    ).bind(since).first()
  ]);

  return cachedJson({
    totals: totals ?? { events: 0, unique_ips: 0, packets: 0, bytes: 0, aggregate_events: 0 },
    timeline: timeline.results,
    topPorts: topPorts.results.map((row) => ({ ...row, key: String(row.key) })),
    topProtocols: topProtocols.results,
    tcpFlags: tcpFlags.results,
    eventKinds: eventKinds.results,
    topBannerIps: topBannerIps.results,
    pcap: pcap ?? { chunks: 0, bytes: 0, packets: 0 }
  });
};
