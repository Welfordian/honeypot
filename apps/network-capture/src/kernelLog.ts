import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import type { NetworkCaptureConfig } from "./config.js";
import { packetEvent, sendEvent, type KernelPacket } from "./events.js";
import { warnThrottled } from "./logging.js";

interface Aggregate {
  firstSeen: string;
  lastSeen: string;
  packetCount: number;
  byteCount: number;
  packet: KernelPacket;
}

const PREFIX = "HP_CAPTURE:";
const aggregates = new Map<string, Aggregate>();
const detailCounts = new Map<string, number>();

function field(line: string, name: string): string | undefined {
  return line.match(new RegExp(`(?:^|\\s)${name}=([^\\s]+)`))?.[1];
}

function flags(line: string): string | undefined {
  const names = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"];
  const found = names.filter((name) => new RegExp(`(?:^|\\s)${name}(?:\\s|$)`).test(line));
  return found.length ? found.join(",") : undefined;
}

function parseKernelLine(line: string): KernelPacket | null {
  if (!line.includes(PREFIX)) return null;
  const sourceIp = field(line, "SRC");
  const protocol = field(line, "PROTO");
  if (!sourceIp || !protocol) return null;

  const length = Number(field(line, "LEN") ?? 0);
  const sourcePort = Number(field(line, "SPT") ?? "");
  const destinationPort = Number(field(line, "DPT") ?? "");

  const packet: KernelPacket = {
    occurredAt: new Date().toISOString(),
    sourceIp,
    protocol: protocol.toLowerCase(),
  };
  const interfaceName = field(line, "IN");
  const destinationIp = field(line, "DST");
  const tcpFlags = flags(line);
  if (interfaceName) packet.interfaceName = interfaceName;
  if (Number.isInteger(sourcePort)) packet.sourcePort = sourcePort;
  if (destinationIp) packet.destinationIp = destinationIp;
  if (Number.isInteger(destinationPort)) packet.destinationPort = destinationPort;
  if (Number.isFinite(length)) packet.length = length;
  if (tcpFlags) packet.tcpFlags = tcpFlags;
  return packet;
}

function aggregateKey(packet: KernelPacket): string {
  const bucket = packet.occurredAt.slice(0, 16);
  return [bucket, packet.sourceIp, packet.protocol, packet.destinationPort ?? "none"].join("|");
}

async function emitAggregate(config: NetworkCaptureConfig, aggregate: Aggregate): Promise<void> {
  const event = packetEvent(config, aggregate.packet);
  if (!event) return;
  event.eventKind = "network-attempt";
  event.occurredAt = aggregate.lastSeen;
  event.network = {
    ...event.network,
    packetCount: aggregate.packetCount,
    byteCount: aggregate.byteCount,
    aggregate: true
  };
  event.tags = ["network", "passive", "aggregate"];
  event.raw = {
    ...event.raw,
    firstSeen: aggregate.firstSeen,
    lastSeen: aggregate.lastSeen
  };
  await sendEvent(config, event);
}

async function handlePacket(config: NetworkCaptureConfig, packet: KernelPacket): Promise<void> {
  if (config.SUPPRESSED_SOURCE_IPS.includes(packet.sourceIp)) return;
  const key = aggregateKey(packet);
  const count = (detailCounts.get(key) ?? 0) + 1;
  detailCounts.set(key, count);

  if (count <= config.METADATA_DETAIL_LIMIT_PER_KEY) {
    const event = packetEvent(config, packet);
    if (event) await sendEvent(config, event);
    return;
  }

  const existing = aggregates.get(key);
  if (existing) {
    existing.lastSeen = packet.occurredAt;
    existing.packetCount += 1;
    existing.byteCount += packet.length ?? 0;
  } else {
    aggregates.set(key, {
      firstSeen: packet.occurredAt,
      lastSeen: packet.occurredAt,
      packetCount: 1,
      byteCount: packet.length ?? 0,
      packet
    });
  }
}

export function startKernelLogFollower(config: NetworkCaptureConfig): ChildProcess {
  const child = spawn("journalctl", ["-kf", "-o", "short-iso"], { stdio: ["ignore", "pipe", "pipe"] });
  if (!child.stdout || !child.stderr) throw new Error("journalctl stdio unavailable");
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    const packet = parseKernelLine(line);
    if (!packet) return;
    handlePacket(config, packet).catch((error) => warnThrottled("network-metadata", "failed to ship network metadata", error));
  });
  child.stderr.on("data", (chunk) => console.warn(`journalctl: ${chunk.toString("utf8").trim()}`));

  setInterval(() => {
    const entries = Array.from(aggregates.entries());
    aggregates.clear();
    detailCounts.clear();
    for (const [, aggregate] of entries) {
      emitAggregate(config, aggregate).catch((error) => warnThrottled("network-aggregate", "failed to flush network aggregate", error));
    }
  }, config.METADATA_AGGREGATE_FLUSH_MS).unref();

  return child;
}
