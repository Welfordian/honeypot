import type { PagesCtx } from "../../_lib/env";
import { parseLimit, parseSinceHours, text, urlOf } from "../../_lib/http";

interface NetworkExportRow {
  occurred_at: string;
  source_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  event_kind: string;
  trap: string;
  packet_count: number;
  byte_count: number;
  tcp_flags: string | null;
  is_aggregate: number;
  pcap_sha256: string | null;
}

function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? "" : String(value);
  return `"${raw.replaceAll("\"", "\"\"")}"`;
}

export const onRequestGet: PagesFunction<PagesCtx["env"]> = async (ctx) => {
  const url = urlOf(ctx.request);
  const sinceHours = parseSinceHours(url, 24, 24 * 30);
  const limit = parseLimit(url, 5000, 10000);
  const result = await ctx.env.DB.prepare(
    `SELECT occurred_at, source_ip, source_port, destination_port, protocol, event_kind, trap,
       packet_count, byte_count, tcp_flags, is_aggregate, pcap_sha256
     FROM events
     WHERE event_kind IN ('network-attempt', 'tcp-banner')
       AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
     ORDER BY occurred_at DESC
     LIMIT ?`
  ).bind(`-${sinceHours} hours`, limit).all<NetworkExportRow>();

  const header = [
    "occurred_at",
    "source_ip",
    "source_port",
    "destination_port",
    "protocol",
    "event_kind",
    "trap",
    "packet_count",
    "byte_count",
    "tcp_flags",
    "is_aggregate",
    "pcap_sha256"
  ];
  const rows = result.results.map((row) => header.map((key) => csvCell(row[key as keyof NetworkExportRow])).join(","));
  return text(`${header.join(",")}\n${rows.join("\n")}${rows.length ? "\n" : ""}`, "text/csv; charset=utf-8");
};
