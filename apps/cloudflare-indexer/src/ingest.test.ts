import { describe, expect, it } from "vitest";
import { normalizeForR2, objectKey } from "./ingest.js";

describe("Cloudflare ingest normalization", () => {
  it("assigns safe storage metadata and deterministic object paths", async () => {
    const event = await normalizeForR2(
      {
        eventId: "00000000-0000-4000-8000-000000000001",
        occurredAt: "2026-06-29T17:00:00.000Z",
        sensorId: "web",
        trap: "env-file",
        protocol: "http",
        source: { ip: "::ffff:203.0.113.10" },
        http: { path: "/.env" }
      },
      32768
    );

    expect(event.source.ip).toBe("203.0.113.10");
    expect(event.severity).toBeGreaterThan(1);
    expect(objectKey("raw", event)).toBe("raw/2026/06/29/17/00000000-0000-4000-8000-000000000001.json");
  });

  it("stores bounded payload metadata without executable handling", async () => {
    const event = await normalizeForR2(
      {
        sensorId: "web",
        trap: "login",
        protocol: "http",
        source: { ip: "203.0.113.10" },
        payload: { text: "x".repeat(100), mimeGuess: "text/plain" }
      },
      12
    );

    expect(event.payloadMeta?.sizeBytes).toBe(12);
    expect(event.payloadMeta?.sha256).toHaveLength(64);
    expect(event.payload?.text).toBe("xxxxxxxxxxxx");
  });

  it("normalizes network metadata without raw pcap object data", async () => {
    const event = await normalizeForR2(
      {
        eventKind: "network-attempt",
        sensorId: "network",
        trap: "network-attempt",
        protocol: "tcp",
        source: { ip: "203.0.113.10", port: 55000 },
        destination: { port: 65001 },
        network: {
          packetCount: 5,
          byteCount: 300,
          tcpFlags: "SYN",
          aggregate: true,
          pcapSha256: "a".repeat(64),
          interfaceName: "enp1s0"
        }
      },
      32768
    );

    expect(event.eventKind).toBe("network-attempt");
    expect(event.network).toMatchObject({
      packetCount: 5,
      byteCount: 300,
      tcpFlags: "SYN",
      aggregate: true,
      pcapSha256: "a".repeat(64)
    });
    expect(JSON.stringify(event)).not.toContain(".pcap");
  });
});
