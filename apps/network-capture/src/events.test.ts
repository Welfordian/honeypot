import { describe, expect, it } from "vitest";
import type { NetworkCaptureConfig } from "./config";
import { packetEvent } from "./events";

const config: NetworkCaptureConfig = {
  SENSOR_ID: "desktopc-network-1",
  INGEST_HMAC_SECRET: "x".repeat(32),
  COLLECTOR_URL: "http://127.0.0.1:3100/internal/ingest/events",
  CLOUDFLARE_PCAP_INGEST_URL: "https://example.com/internal/ingest/pcap",
  CAPTURE_INTERFACE: "enp1s0",
  PUBLIC_IP: "203.0.113.20",
  SUPPRESSED_SOURCE_IPS: ["203.0.113.10"],
  ADMIN_SSH_PORT: 22222,
  GENERIC_BANNER_PORT: 65000,
  PCAP_SPOOL_DIR: "/tmp/honeypot-capture",
  PCAP_ROTATE_SECONDS: 60,
  PCAP_MAX_MB: 8,
  PCAP_UPLOAD_MIN_AGE_MS: 7000,
  PCAP_MAX_SPOOL_BYTES: 268435456,
  INGEST_TIMEOUT_MS: 8000,
  INGEST_CONCURRENCY: 4,
  INGEST_QUEUE_MAX: 5000,
  METADATA_DETAIL_LIMIT_PER_KEY: 25,
  METADATA_AGGREGATE_FLUSH_MS: 30000,
  MAX_BANNER_BYTES: 512,
  BANNER_CLOSE_AFTER_MS: 5000
};

describe("network capture events", () => {
  it("drops suppressed source IPs before event creation", () => {
    expect(
      packetEvent(config, {
        occurredAt: "2026-06-29T22:00:00.000Z",
        sourceIp: "203.0.113.10",
        destinationPort: 443,
        protocol: "tcp"
      })
    ).toBeNull();
  });

  it("creates public-safe network attempt metadata", () => {
    expect(
      packetEvent(config, {
        occurredAt: "2026-06-29T22:00:00.000Z",
        interfaceName: "enp1s0",
        sourceIp: "203.0.113.20",
        sourcePort: 44123,
        destinationIp: "203.0.113.20",
        destinationPort: 65001,
        protocol: "tcp",
        length: 60,
        tcpFlags: "SYN"
      })
    ).toMatchObject({
      eventKind: "network-attempt",
      trap: "network-attempt",
      protocol: "tcp",
      source: { ip: "203.0.113.20", port: 44123 },
      destination: { port: 65001 },
      network: { packetCount: 1, byteCount: 60, tcpFlags: "SYN", aggregate: false },
      tags: ["network", "passive"]
    });
  });
});
