import type { PagesCtx } from "../../_lib/env";
import { cachedJson, parseSinceHours, urlOf } from "../../_lib/http";
import {
  FAST_CACHE,
  sumRollupAmountForKey,
  sumRollupCounts,
  sumRollupCountsForKeys,
  sumRollupCountForKey,
  sumRollupEventTotalsForKinds,
  sumRollupTimelineWithUniqueIpsForKinds
} from "../../_lib/rollups";

const NETWORK_KINDS = ["network-attempt", "tcp-banner"];

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const since = `-${sinceHours} hours`;

  const [rollupTotals, timeline, topPorts, topProtocols, tcpFlags, eventKinds, topBannerIps, pcap, packets, bytes, aggregateEvents] =
    await Promise.all([
      sumRollupEventTotalsForKinds(ctx.env.DB, since, NETWORK_KINDS),
      sumRollupTimelineWithUniqueIpsForKinds(ctx.env.DB, since, NETWORK_KINDS),
      sumRollupCounts(ctx.env.DB, "net_destination_port", since, 20),
      sumRollupCounts(ctx.env.DB, "net_protocol", since, 20),
      sumRollupCounts(ctx.env.DB, "net_tcp_flags", since, 20),
      sumRollupCountsForKeys(ctx.env.DB, "event_kind", NETWORK_KINDS, since),
      sumRollupCounts(ctx.env.DB, "net_banner_ip", since, 20),
      ctx.env.DB.prepare(
        `SELECT COUNT(*) AS chunks, COALESCE(SUM(size_bytes), 0) AS bytes, COALESCE(SUM(packet_count), 0) AS packets
         FROM pcap_chunks
         WHERE uploaded_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)`
      )
        .bind(since)
        .first<{ chunks: number; bytes: number; packets: number }>(),
      sumRollupAmountForKey(ctx.env.DB, "net_packets", "total", since),
      sumRollupAmountForKey(ctx.env.DB, "net_bytes", "total", since),
      sumRollupCountForKey(ctx.env.DB, "net_aggregate", "1", since)
    ]);

  return cachedJson(
    {
      totals: {
        events: rollupTotals.events,
        unique_ips: rollupTotals.unique_ips,
        packets,
        bytes,
        aggregate_events: aggregateEvents
      },
      timeline,
      topPorts: topPorts.map((row) => ({ ...row, key: String(row.key) })),
      topProtocols,
      tcpFlags,
      eventKinds,
      topBannerIps: topBannerIps,
      pcap: pcap ?? { chunks: 0, bytes: 0, packets: 0 }
    },
    FAST_CACHE
  );
};
