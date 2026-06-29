import type { HoneypotEvent } from "@honeypot/shared";
import { normalizeIp, safePreview } from "@honeypot/shared";
import type { NetworkCaptureConfig } from "./config.js";
import { signedHeaders } from "./signature.js";

interface SendTask {
  run: () => Promise<void>;
  resolve: () => void;
  reject: (error: unknown) => void;
}

const sendQueue: SendTask[] = [];
let activeSends = 0;

function pumpSendQueue(maxConcurrency: number): void {
  while (activeSends < maxConcurrency) {
    const task = sendQueue.shift();
    if (!task) return;
    activeSends += 1;
    task
      .run()
      .then(task.resolve, task.reject)
      .finally(() => {
        activeSends -= 1;
        pumpSendQueue(maxConcurrency);
      });
  }
}

function enqueueSend(config: NetworkCaptureConfig, run: () => Promise<void>): Promise<void> {
  if (sendQueue.length >= config.INGEST_QUEUE_MAX) {
    return Promise.reject(new Error("ingest send queue full"));
  }

  return new Promise((resolve, reject) => {
    sendQueue.push({ run, resolve, reject });
    pumpSendQueue(config.INGEST_CONCURRENCY);
  });
}

export interface KernelPacket {
  occurredAt: string;
  interfaceName?: string;
  sourceIp: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  protocol: string;
  length?: number;
  tcpFlags?: string;
}

export async function sendEvent(config: NetworkCaptureConfig, event: HoneypotEvent): Promise<void> {
  const sourceIp = normalizeIp(event.source.ip);
  if (config.SUPPRESSED_SOURCE_IPS.includes(sourceIp)) return;

  const raw = JSON.stringify({ ...event, source: { ...event.source, ip: sourceIp } });
  await enqueueSend(config, async () => {
    const response = await fetch(config.COLLECTOR_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...signedHeaders(config.INGEST_HMAC_SECRET, raw)
      },
      body: raw,
      signal: AbortSignal.timeout(config.INGEST_TIMEOUT_MS)
    });
    if (!response.ok) throw new Error(`collector rejected network event with ${response.status}`);
  });
}

export function packetEvent(config: NetworkCaptureConfig, packet: KernelPacket): HoneypotEvent | null {
  const sourceIp = normalizeIp(packet.sourceIp);
  if (config.SUPPRESSED_SOURCE_IPS.includes(sourceIp)) return null;

  return {
    eventKind: "network-attempt",
    occurredAt: packet.occurredAt,
    sensorId: config.SENSOR_ID,
    trap: "network-attempt",
    protocol: packet.protocol.toLowerCase(),
    source: {
      ip: sourceIp,
      port: packet.sourcePort
    },
    destination: {
      port: packet.destinationPort
    },
    network: {
      packetCount: 1,
      byteCount: packet.length ?? 0,
      tcpFlags: packet.tcpFlags,
      aggregate: false,
      interfaceName: packet.interfaceName
    },
    severity: packet.protocol.toLowerCase() === "tcp" ? 2 : 1,
    tags: ["network", "passive"],
    raw: {
      destinationIp: packet.destinationIp,
      interfaceName: packet.interfaceName
    }
  };
}

export function bannerEvent(config: NetworkCaptureConfig, socket: import("node:net").Socket, payload?: Buffer): HoneypotEvent | null {
  const sourceIp = normalizeIp(socket.remoteAddress ?? "0.0.0.0");
  if (config.SUPPRESSED_SOURCE_IPS.includes(sourceIp)) return null;

  return {
    eventKind: "tcp-banner",
    sensorId: config.SENSOR_ID,
    trap: "generic-tcp-banner",
    protocol: "tcp",
    source: {
      ip: sourceIp,
      port: socket.remotePort
    },
    destination: {
      port: config.GENERIC_BANNER_PORT
    },
    payload: payload ? { text: safePreview(payload.subarray(0, config.MAX_BANNER_BYTES).toString("utf8")), mimeGuess: "application/octet-stream" } : undefined,
    network: {
      packetCount: 1,
      byteCount: payload?.byteLength ?? 0,
      aggregate: false,
      interfaceName: config.CAPTURE_INTERFACE
    },
    severity: 3,
    tags: ["network", "tcp-banner", "unknown-port"],
    raw: {
      localPort: socket.localPort,
      originalDestinationPort: "unavailable-after-redirect"
    }
  };
}
